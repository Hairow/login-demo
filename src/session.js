import { parseCookie, stringifyCookie } from "cookie";
import { signJWT, verifyJWT } from "./jwt.js";

// ============================================================
// Session 生命周期
// ============================================================

const SESSION_TTL = 60 * 60 * 24; // 24 小时
const COOKIE_NAME = "Authorization‌";

function buildCookieOptions(request) {
  return {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_TTL,
  };
}

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

  await kv.put(`session:${token}`, JSON.stringify(user), {
    expirationTtl: SESSION_TTL,
  });

  return token;
}

/**
 * 从请求中读取指定 cookie 值
 */
function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  return parseCookie(header)[name] || null;
}

/**
 * 从请求 Cookie 中解析当前用户，未登录返回 null
 */
export async function getCurrentUser(request, env) {
  const token = getCookie(request, COOKIE_NAME);
  if (!token) return null;

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
  const token = getCookie(request, COOKIE_NAME);
  if (token) {
    await kv.delete(`session:${token}`);
  }
}

/**
 * 登录成功：设置 session cookie
 */
export function sessionCookie(token, request) {
  return stringifyCookie(COOKIE_NAME, token, buildCookieOptions(request));
}

/**
 * 登出：清除 session cookie
 */
export function clearCookie(request) {
  return stringifyCookie(COOKIE_NAME, "", { ...buildCookieOptions(request), maxAge: 0 });
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
      "Set-Cookie": clearCookie(request),
    },
  });
}
