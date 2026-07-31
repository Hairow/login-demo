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
    user = provider === "github"
      ? await fetchGitHubUser(tokens.accessToken())
      : await fetchGoogleUser(tokens.accessToken());
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
