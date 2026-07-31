import { SignJWT, jwtVerify } from "jose";

// ============================================================
// JWT（基于 jose 包）
// ============================================================

/**
 * 使用 HMAC-SHA256 签名 JWT
 */
export async function signJWT(payload, secret, ttl = "24h") {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(ttl)
    .sign(new TextEncoder().encode(secret));
}

/**
 * 验证并解析 JWT，失败返回 null
 */
export async function verifyJWT(token, secret) {
  try {
    const { payload } = await jwtVerify(token, new TextEncoder().encode(secret));
    return payload;
  } catch {
    return null;
  }
}

// ============================================================
// 随机字符串（用于 OAuth CSRF state）
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
