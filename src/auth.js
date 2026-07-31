import { randomString } from "./jwt.js";
import { createSession, sessionCookie } from "./session.js";

// ============================================================
// OAuth 2.0 提供商配置
// ============================================================

export const OAUTH_PROVIDERS = {
  github: {
    authUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    userUrl: "https://api.github.com/user",
    emailsUrl: "https://api.github.com/user/emails",
    scope: "read:user user:email",
    async getUser(accessToken) {
      const userResp = await fetch(this.userUrl, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "User-Agent": "login-demo",
        },
      });
      if (!userResp.ok) throw new Error("Failed to fetch GitHub user");
      const user = await userResp.json();

      const emailsResp = await fetch(this.emailsUrl, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "User-Agent": "login-demo",
        },
      });
      let email = null;
      if (emailsResp.ok) {
        const emails = await emailsResp.json();
        const primary = emails.find((e) => e.primary);
        email = primary ? primary.email : (emails[0] ? emails[0].email : null);
      }

      return {
        provider: "github",
        providerId: String(user.id),
        username: user.login,
        name: user.name || user.login,
        email,
        avatar: user.avatar_url,
      };
    },
  },

  google: {
    authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    userUrl: "https://www.googleapis.com/oauth2/v2/userinfo",
    scope: "openid email profile",
    async getUser(accessToken) {
      const resp = await fetch(this.userUrl, {
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
    },
  },
};

// ============================================================
// OAuth 流程
// ============================================================

/**
 * 构建授权 URL（生成 anti-CSRF state 存入 KV，10 分钟有效）
 */
export async function buildAuthUrl(provider, env, redirectUri) {
  const config = OAUTH_PROVIDERS[provider];
  if (!config) return null;

  const state = randomString(32);
  await env.USER_KV.put(`oauth:state:${state}`, provider, { expirationTtl: 600 });

  const clientId = provider === "github" ? env.GITHUB_CLIENT_ID : env.GOOGLE_CLIENT_ID;

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    state,
    scope: config.scope,
    response_type: "code",
  });

  if (provider === "google") {
    params.set("access_type", "offline");
    params.set("prompt", "consent");
  }

  return `${config.authUrl}?${params.toString()}`;
}

/**
 * 处理 OAuth 回调：校验 state -> code 换 token -> 获取用户 -> 创建 session
 */
export async function handleCallback(provider, request, env, redirectUri) {
  const config = OAUTH_PROVIDERS[provider];
  if (!config) {
    return new Response(JSON.stringify({ error: "unsupported provider" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error) {
    return new Response(JSON.stringify({ error: `OAuth error: ${error}` }), {
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

  // 校验 state
  const storedProvider = await env.USER_KV.get(`oauth:state:${state}`);
  if (storedProvider !== provider) {
    return new Response(JSON.stringify({ error: "invalid state" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }
  await env.USER_KV.delete(`oauth:state:${state}`);

  // code 换 token
  const clientId = provider === "github" ? env.GITHUB_CLIENT_ID : env.GOOGLE_CLIENT_ID;
  const clientSecret = provider === "github" ? env.GITHUB_CLIENT_SECRET : env.GOOGLE_CLIENT_SECRET;

  const tokenResp = await fetch(config.tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    }),
  });

  if (!tokenResp.ok) {
    const errText = await tokenResp.text();
    return new Response(JSON.stringify({ error: "token exchange failed", detail: errText }), {
      status: 502,
      headers: { "Content-Type": "application/json" },
    });
  }

  const tokenData = await tokenResp.json();
  if (tokenData.error) {
    return new Response(JSON.stringify({ error: tokenData.error, description: tokenData.error_description }), {
      status: 502,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 获取用户信息
  const user = await config.getUser(tokenData.access_token);

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
