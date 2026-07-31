import { GitHub, Google } from "arctic";
import { nanoid } from "nanoid"
import { createSession, sessionCookie } from "./session.js";

// ============================================================
// OAuth 2.0 用户信息获取（arctic 不处理此步）
// ============================================================

async function fetchGitHubUser(accessToken) {
  const [userResp, emailsResp] = await Promise.all([
    fetch("https://api.github.com/user", {
      headers: { Authorization: `Bearer ${accessToken}`, "User-Agent": "login-demo" },
    }),
    fetch("https://api.github.com/user/emails", {
      headers: { Authorization: `Bearer ${accessToken}`, "User-Agent": "login-demo" },
    }),
  ]);

  if (!userResp.ok) throw new Error("Failed to fetch GitHub user");
  const user = await userResp.json();

  let email = null;
  if (emailsResp.ok) {
    const emails = await emailsResp.json();
    const primary = emails.find((e) => e.primary);
    email = primary ? primary.email : emails[0]?.email ?? null;
  }

  return {
    provider: "github",
    providerId: String(user.id),
    username: user.login,
    name: user.name || user.login,
    email,
    avatar: user.avatar_url,
  };
}

async function fetchGoogleUser(accessToken) {
  const resp = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!resp.ok) throw new Error("Failed to fetch Google user");
  const user = await resp.json();

  return {
    provider: "google",
    providerId: user.id,
    username: user.email,
    name: user.name || user.email,
    email: user.email,
    avatar: user.picture,
  };
}

// ---------- 微信 ----------

async function fetchWechatUser(accessToken, openid) {
  const resp = await fetch(
    `https://api.weixin.qq.com/sns/userinfo?access_token=${encodeURIComponent(accessToken)}&openid=${encodeURIComponent(openid)}&lang=zh_CN`
  );
  if (!resp.ok) throw new Error("Failed to fetch WeChat user");
  const data = await resp.json();
  if (data.errcode) throw new Error(`WeChat API error: ${data.errmsg}`);

  return {
    provider: "wechat",
    providerId: data.unionid || data.openid,
    username: data.nickname,
    name: data.nickname,
    email: null,                     // 微信不返回邮箱
    avatar: data.headimgurl,
  };
}

// ---------- QQ ----------

async function fetchQQOpenId(accessToken) {
  const resp = await fetch(
    `https://graph.qq.com/oauth2.0/me?access_token=${encodeURIComponent(accessToken)}&fmt=json`
  );
  if (!resp.ok) throw new Error("Failed to fetch QQ openid");
  const data = await resp.json();
  if (data.error) throw new Error(`QQ openid error: ${data.error_description || data.error}`);
  return { openid: data.openid, unionid: data.unionid };
}

async function fetchQQUser(accessToken, appId, openid) {
  const resp = await fetch(
    `https://graph.qq.com/user/get_user_info?access_token=${encodeURIComponent(accessToken)}&oauth_consumer_key=${encodeURIComponent(appId)}&openid=${encodeURIComponent(openid)}`
  );
  if (!resp.ok) throw new Error("Failed to fetch QQ user");
  const data = await resp.json();
  if (data.ret !== 0) throw new Error(`QQ API error: ${data.msg}`);

  return {
    provider: "qq",
    providerId: data.unionid || openid,
    username: data.nickname,
    name: data.nickname,
    email: null,                     // QQ 不返回邮箱
    avatar: data.figureurl_qq_2 || data.figureurl_2 || data.figureurl_qq_1 || data.figureurl_1,
  };
}

// ============================================================
// OAuth 流程（token 交换由 arctic 处理）
// ============================================================

const OAUTH_STATE_TTL = 600; // 10 分钟

/**
 * 构建授权 URL（arctic 生成，state/PKCE 存入 KV）
 */
export async function buildAuthUrl(provider, env, redirectUri) {
  const state = nanoid(32);
  await env.USER_KV.put(`oauth:state:${state}`, provider, { expirationTtl: OAUTH_STATE_TTL });

  if (provider === "github") {
    const github = new GitHub(env.GITHUB_CLIENT_ID, env.GITHUB_CLIENT_SECRET, redirectUri);
    return github.createAuthorizationURL(state, ["read:user", "user:email"]).toString();
  }

  if (provider === "google") {
    // Google 强制 PKCE
    const codeVerifier = nanoid(64);
    await env.USER_KV.put(`oauth:pkce:${state}`, codeVerifier, { expirationTtl: OAUTH_STATE_TTL });

    const google = new Google(env.GOOGLE_CLIENT_ID, env.GOOGLE_CLIENT_SECRET, redirectUri);
    return google.createAuthorizationURL(state, codeVerifier, ["openid", "email", "profile"]).toString();
  }

  // ---------- 微信网站应用扫码登录 ----------
  // https://open.weixin.qq.com/connect/qrconnect
  //   ?appid=APPID
  //   &redirect_uri=URI（已编码）
  //   &response_type=code
  //   &scope=snsapi_login
  //   &state=STATE
  //   #wechat_redirect（必须，微信内嵌 JS 用来关闭弹窗）
  if (provider === "wechat") {
    const params = new URLSearchParams({
      appid: env.WECHAT_APP_ID,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "snsapi_login",
      state,
    });
    return `https://open.weixin.qq.com/connect/qrconnect?${params.toString()}#wechat_redirect`;
  }

  // ---------- QQ互联网站应用登录 ----------
  // https://graph.qq.com/oauth2.0/authorize
  //   ?response_type=code
  //   &client_id=APPID
  //   &redirect_uri=URI（已编码）
  //   &scope=get_user_info
  //   &state=STATE
  if (provider === "qq") {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: env.QQ_APP_ID,
      redirect_uri: redirectUri,
      scope: "get_user_info",
      state,
    });
    return `https://graph.qq.com/oauth2.0/authorize?${params.toString()}`;
  }

  return null;
}

/**
 * 处理 OAuth 回调：校验 state -> arctic 换 token -> 获取用户 -> 创建 session
 */
export async function handleCallback(provider, request, env, redirectUri) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const oauthError = url.searchParams.get("error");

  if (oauthError) {
    return new Response(JSON.stringify({ error: `OAuth error: ${oauthError}` }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }
  if (!code || !state) {
    return new Response(JSON.stringify({ error: "missing code or state" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 校验 state（防 CSRF）
  const storedProvider = await env.USER_KV.get(`oauth:state:${state}`);
  if (storedProvider !== provider) {
    return new Response(JSON.stringify({ error: "invalid state" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  let tokens;
  try {
    if (provider === "github") {
      const github = new GitHub(env.GITHUB_CLIENT_ID, env.GITHUB_CLIENT_SECRET, redirectUri);
      tokens = await github.validateAuthorizationCode(code);
    } else if (provider === "google") {
      const codeVerifier = await env.USER_KV.get(`oauth:pkce:${state}`);
      if (!codeVerifier) {
        return new Response(JSON.stringify({ error: "missing PKCE verifier" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        });
      }
      await env.USER_KV.delete(`oauth:pkce:${state}`);
      const google = new Google(env.GOOGLE_CLIENT_ID, env.GOOGLE_CLIENT_SECRET, redirectUri);
      tokens = await google.validateAuthorizationCode(code, codeVerifier);
    } else if (provider === "wechat") {
      // 微信 token 交换：纯 GET 请求，响应为 JSON
      const tokenUrl = `https://api.weixin.qq.com/sns/oauth2/access_token?appid=${env.WECHAT_APP_ID}&secret=${env.WECHAT_APP_SECRET}&code=${code}&grant_type=authorization_code`;
      const resp = await fetch(tokenUrl);
      const data = await resp.json();
      if (data.errcode) {
        return new Response(JSON.stringify({ error: "WeChat token exchange failed", detail: data.errmsg }), {
          status: 502, headers: { "Content-Type": "application/json" },
        });
      }
      // 包装为统一格式：{ accessToken, openid, unionid }
      tokens = { accessToken: data.access_token, openid: data.openid, unionid: data.unionid };
    } else if (provider === "qq") {
      // QQ token 交换：GET 请求，fmt=json 确保返回 JSON（否则默认是 callback）
      const tokenUrl = `https://graph.qq.com/oauth2.0/token?grant_type=authorization_code&client_id=${env.QQ_APP_ID}&client_secret=${env.QQ_APP_KEY}&code=${code}&redirect_uri=${encodeURIComponent(redirectUri)}&fmt=json`;
      const resp = await fetch(tokenUrl);
      const body = await resp.text();
      let data;
      try {
        data = JSON.parse(body);
      } catch {
        return new Response(JSON.stringify({ error: "QQ token response parse failed", detail: body }), {
          status: 502, headers: { "Content-Type": "application/json" },
        });
      }
      if (data.error) {
        return new Response(JSON.stringify({ error: "QQ token exchange failed", detail: data.error_description }), {
          status: 502, headers: { "Content-Type": "application/json" },
        });
      }
      tokens = { accessToken: data.access_token };
    } else {
      return new Response(JSON.stringify({ error: "unsupported provider" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }
  } catch (err) {
    return new Response(JSON.stringify({ error: "token exchange failed", detail: err.message }), {
      status: 502,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 清理 state
  await env.USER_KV.delete(`oauth:state:${state}`);

  // 获取用户信息
  let user;
  try {
    if (provider === "github") {
      user = await fetchGitHubUser(tokens.accessToken());
    } else if (provider === "google") {
      user = await fetchGoogleUser(tokens.accessToken());
    } else if (provider === "wechat") {
      user = await fetchWechatUser(tokens.accessToken, tokens.openid);
    } else if (provider === "qq") {
      // QQ 需要先拿 openid，再取用户信息
      const { openid, unionid } = await fetchQQOpenId(tokens.accessToken);
      user = await fetchQQUser(tokens.accessToken, env.QQ_APP_ID, openid);
      // 合并 unionid（fetchQQOpenId 返回的 unionid 可能更新）
      if (unionid) user.providerId = unionid;
    } else {
      throw new Error(`unsupported provider: ${provider}`);
    }
  } catch (err) {
    return new Response(JSON.stringify({ error: "failed to fetch user", detail: err.message }), {
      status: 502,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 创建 session
  const token = await createSession(env.USER_KV, env.JWT_SECRET, user);

  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": sessionCookie(token),
    },
  });
}
