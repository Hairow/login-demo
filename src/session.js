import { parseCookie, stringifySetCookie } from "cookie";
import { SignJWT, jwtVerify } from "jose";

// ============================================================
// Session 生命周期
// ============================================================

const SESSION_TTL = 60 * 60 * 24; // 24 小时
const COOKIE_NAME = "Authorization‌";

/**
 * 对 token 做 SHA-256 哈希，生成定长的 KV key
 */
async function hashToken(token) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * 拼接完整的 KV session key
 */
async function sessionKVKey(token) {
  return `session:${await hashToken(token)}`;
}

function buildCookieOptions(request) {
  return {
    httpOnly: true,
    secure: new URL(request.url).protocol === "https:",
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_TTL,
  };
}

/**
 * 创建 session，写入 KV 并返回 JWT token
 */
function encodeSecret(secret) {
  return new TextEncoder().encode(secret);
}

export async function createSession(kv, jwtSecret, user) {
  const token = await new SignJWT({
    sub: `${user.provider}:${user.providerId}`,
    username: user.username,
    name: user.name,
    email: user.email,
    avatar: user.avatar,
    provider: user.provider,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(SESSION_TTL)
    .sign(encodeSecret(jwtSecret));

  await kv.put(await sessionKVKey(token), "1", {
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
  let payload;
  try {
    const result = await jwtVerify(token, encodeSecret(env.JWT_SECRET));
    payload = result.payload;
  } catch {
    return null;
  }

  // 2. KV 校验（支持主动失效）
  const session = await env.USER_KV.get(await sessionKVKey(token));
  if (!session) return null;

  return payload;
}

/**
 * 清除 session（从 KV 删除）
 */
export async function destroySession(kv, request) {
  const token = getCookie(request, COOKIE_NAME);
  if (token) {
    await kv.delete(await sessionKVKey(token));
  }
}

/**
 * 登录成功：设置 session cookie
 */
export function sessionCookie(token, request) {
  return stringifySetCookie({ name: COOKIE_NAME, value: token, ...buildCookieOptions(request) });
}

/**
 * 登出：清除 session cookie
 */
export function clearCookie(request) {
  return stringifySetCookie({ name: COOKIE_NAME, value: "", ...buildCookieOptions(request), maxAge: 0 });
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
