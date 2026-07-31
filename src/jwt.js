import { SignJWT, jwtVerify } from "jose";

// ============================================================
// JWT（基于 jose）
// ============================================================

/**
 * HMAC-SHA256 签名 JWT
 */
export async function signJWT(payload, secret, ttl = "24h") {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(ttl)
    .sign(new TextEncoder().encode(secret));
}

/**
 * 验证 JWT，失败返回 null
 */
export async function verifyJWT(token, secret) {
  try {
    const { payload } = await jwtVerify(token, new TextEncoder().encode(secret));
    return payload;
  } catch {
    return null;
  }
}
