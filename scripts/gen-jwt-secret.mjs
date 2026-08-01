/**
 * 使用项目中的 jose 包生成 JWT_SECRET (HS256)
 * 用法: node scripts/gen-jwt-secret.mjs
 */
import { generateSecret } from "jose";

const key = await generateSecret("HS256", { extractable: true });
const raw = await crypto.subtle.exportKey("raw", key);
const hex = Buffer.from(raw).toString("hex");

console.log(hex);
