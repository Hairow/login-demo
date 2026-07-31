import { signJWT, verifyJWT } from "./jwt.js";

// ============================================================
// Session 生命周期
// ============================================================

const SESSION_TTL = 60 * 60 * 24; // 24 小时
const COOKIE_NAME = "session_token";

/**
 * 创建 session，写入 KV 并返回 JWT token
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
    },
    jwtSecret,
    "24h"
  );

  // KV 备份，支持主动失效
  await kv.put(`session:${token}`, JSON.stringify(user), {
    expirationTtl: SESSION_TTL,
  });

  return token;
}

/**
 * 从请求 Cookie 中解析当前用户，未登录返回 null
 */
export async function getCurrentUser(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp(`${COOKIE_NAME}=([^;]+)`));
  if (!match) return null;

  const token = match[1];

  // 1. JWT 校验
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) return null;

  // 2. KV 校验（支持主动失效）
  const session = await env.USER_KV.get(`session:${token}`);
  if (!session) return null;

  return payload;
}

/**
 * 清除 session（从 KV 删除）
 */
export async function destroySession(kv, request) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp(`${COOKIE_NAME}=([^;]+)`));
  if (match) {
    await kv.delete(`session:${match[1]}`);
  }
}

/**
 * 构建 set-cookie header 值
 */
function cookieHeader(value, maxAge) {
  return `${COOKIE_NAME}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

/**
 * 登录成功：设置 session cookie
 */
export function sessionCookie(token) {
  return cookieHeader(token, SESSION_TTL);
}

/**
 * 登出：清除 session cookie
 */
export function clearCookie() {
  return cookieHeader("", 0);
}

/**
 * 构建登出响应（302 到首页）
 */
export async function buildLogoutResponse(kv, request) {
  await destroySession(kv, request);
  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": clearCookie(),
    },
  });
}
