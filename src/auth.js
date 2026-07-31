// ============================================================
// JWT 工具（Web Crypto API 实现）
// ============================================================

function base64url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64urlDecode(str) {
  // 补齐 padding 并还原标准 base64
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * 使用 HMAC-SHA256 签名 JWT
 */
export async function signJWT(payload, secret) {
  const encoder = new TextEncoder();
  const header = { alg: "HS256", typ: "JWT" };

  const encodedHeader = base64url(encoder.encode(JSON.stringify(header)));
  const encodedPayload = base64url(encoder.encode(JSON.stringify(payload)));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(signingInput));
  const encodedSig = base64url(new Uint8Array(sig));

  return `${encodedHeader}.${encodedPayload}.${encodedSig}`;
}

/**
 * 验证并解析 JWT，失败返回 null
 */
export async function verifyJWT(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [encodedHeader, encodedPayload, encodedSig] = parts;
    const encoder = new TextEncoder();

    // 验证签名
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const sigBytes = base64urlDecode(encodedSig);

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBytes,
      encoder.encode(signingInput)
    );

    if (!valid) return null;

    // 解析 payload
    const payloadBytes = base64urlDecode(encodedPayload);
    const payload = JSON.parse(new TextDecoder().decode(payloadBytes));

    // 检查过期
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;

    return payload;
  } catch {
    return null;
  }
}

// ============================================================
// 随机字符串生成
// ============================================================

const CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

export function randomString(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let result = "";
  for (let i = 0; i < length; i++) {
    result += CHARS[bytes[i] % CHARS.length];
  }
  return result;
}

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
    /**
     * 用 access_token 换取用户信息
     */
    async getUser(accessToken) {
      const userResp = await fetch(this.userUrl, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "User-Agent": "login-demo",
        },
      });

      if (!userResp.ok) throw new Error("Failed to fetch GitHub user");

      const user = await userResp.json();

      // 获取邮箱
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
    /**
     * 用 access_token 换取用户信息
     */
    async getUser(accessToken) {
      const resp = await fetch(this.userUrl, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      if (!resp.ok) throw new Error("Failed to fetch Google user");

      const user = await resp.json();

      return {
        provider: "google",
        providerId: user.id,
        username: user.email, // Google 没有 username，用邮箱代替
        name: user.name || user.email,
        email: user.email,
        avatar: user.picture,
      };
    },
  },
};

// ============================================================
// Session 管理
// ============================================================

const SESSION_TTL = 60 * 60 * 24; // 24 小时

/**
 * 创建 session，返回 JWT token
 */
export async function createSession(kv, jwtSecret, user) {
  const token = await signJWT(
    {
      sub: `${user.provider}:${user.providerId}`,
      username: user.username,
      name: user.name,
      email: user.email,
      avatar: user.avatar,
      provider: user.provider,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + SESSION_TTL,
    },
    jwtSecret
  );

  // 同时存入 KV，支持主动失效
  await kv.put(`session:${token}`, JSON.stringify(user), {
    expirationTtl: SESSION_TTL,
  });

  return token;
}

/**
 * 从请求中获取当前用户，未登录返回 null
 */
export async function getCurrentUser(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/session_token=([^;]+)/);
  if (!match) return null;

  const token = match[1];
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) return null;

  // 检查 KV 中 session 是否存在（支持主动失效）
  const session = await env.USER_KV.get(`session:${token}`);
  if (!session) return null;

  return payload;
}

/**
 * 从请求中获取用户，未登录返回 401
 */
export async function requireUser(request, env) {
  const user = await getCurrentUser(request, env);
  if (!user) {
    throw new Response(
      JSON.stringify({ error: "unauthorized" }),
      { status: 401, headers: { "Content-Type": "application/json" } }
    );
  }
  return user;
}

/**
 * 清除 session
 */
export async function destroySession(kv, request) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/session_token=([^;]+)/);
  if (match) {
    await kv.delete(`session:${match[1]}`);
  }
}

// ============================================================
// OAuth 流程：构建授权 URL
// ============================================================

export async function buildAuthUrl(provider, env, redirectUri) {
  const config = OAUTH_PROVIDERS[provider];
  if (!config) return null;

  // 生成 CSRF state，存入 KV（10 分钟有效）
  const state = randomString(32);
  await env.USER_KV.put(`oauth:state:${state}`, provider, {
    expirationTtl: 600,
  });

  const clientId = provider === "github" ? env.GITHUB_CLIENT_ID : env.GOOGLE_CLIENT_ID;

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    state,
    scope: config.scope,
    response_type: "code",
  });

  // Google 额外参数
  if (provider === "google") {
    params.set("access_type", "offline");
    params.set("prompt", "consent");
  }

  return `${config.authUrl}?${params.toString()}`;
}

// ============================================================
// OAuth 流程：处理回调
// ============================================================

export async function handleCallback(provider, request, env, redirectUri) {
  const config = OAUTH_PROVIDERS[provider];
  if (!config) {
    return new Response(
      JSON.stringify({ error: "unsupported provider" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error) {
    return new Response(
      JSON.stringify({ error: `OAuth error: ${error}` }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  if (!code || !state) {
    return new Response(
      JSON.stringify({ error: "missing code or state" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  // 验证 state（防 CSRF）
  const storedProvider = await env.USER_KV.get(`oauth:state:${state}`);
  if (storedProvider !== provider) {
    return new Response(
      JSON.stringify({ error: "invalid state" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  // 一次性使用，用完删除
  await env.USER_KV.delete(`oauth:state:${state}`);

  // 用 code 换 access_token
  const clientId = provider === "github" ? env.GITHUB_CLIENT_ID : env.GOOGLE_CLIENT_ID;
  const clientSecret = provider === "github" ? env.GITHUB_CLIENT_SECRET : env.GOOGLE_CLIENT_SECRET;

  const tokenResp = await fetch(config.tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
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
    return new Response(
      JSON.stringify({ error: "token exchange failed", detail: errText }),
      { status: 502, headers: { "Content-Type": "application/json" } }
    );
  }

  const tokenData = await tokenResp.json();

  if (tokenData.error) {
    return new Response(
      JSON.stringify({ error: tokenData.error, description: tokenData.error_description }),
      { status: 502, headers: { "Content-Type": "application/json" } }
    );
  }

  // 用 access_token 获取用户信息
  const user = await config.getUser(tokenData.access_token);

  // 创建 session
  const sessionToken = await createSession(env.USER_KV, env.JWT_SECRET, user);

  // 设置 cookie 并重定向到首页
  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": `session_token=${sessionToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${86400}`,
    },
  });
}

/**
 * 构建登出响应
 */
export async function buildLogoutResponse(kv, request) {
  await destroySession(kv, request);
  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": "session_token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
    },
  });
}
