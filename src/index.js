import { Router, error, json } from "itty-router";
import { buildAuthUrl, handleCallback } from "./auth.js";
import { getCurrentUser, buildLogoutResponse } from "./session.js";

// ============================================================
// 公开路由白名单
// ============================================================

const PUBLIC_PATHS = new Set([
  "/auth/github",
  "/auth/github/callback",
  "/auth/google",
  "/auth/google/callback",
  "/auth/logout",
  "/health",
]);

// ============================================================
// 鉴权中间件：非公开路由未登录 -> 302 /index.html
// ============================================================

async function authGuard(request, env) {
  if (PUBLIC_PATHS.has(new URL(request.url).pathname)) return;

  const user = await getCurrentUser(request, env);
  if (!user) {
    return Response.redirect("/index.html", 302);
  }
  // 将用户挂到 request 上，后续 handler 可直接使用
  request.user = user;
}

// ============================================================
// 构造函数工具
// ============================================================

function baseUrl(request) {
  const u = new URL(request.url);
  return `${u.protocol}//${u.host}`;
}

// ============================================================
// 路由定义
// ============================================================

const router = Router();

// --- 首页 ---
router.get("/", (request, env) => {
  return request.user
    ? Response.redirect("/user", 302)
    : Response.redirect("/index.html", 302);
});

// --- 用户信息页（需登录） ---
router.get("/user", (request) => {
  const { username, name, email, avatar, provider } = request.user;
  return json({ username, name, email, avatar, provider });
});

// --- OAuth: GitHub ---
router.get("/auth/github", async (request, env) => {
  const url = await buildAuthUrl("github", env, `${baseUrl(request)}/auth/github/callback`);
  if (!url) return json({ error: "GitHub not configured" }, 500);
  return Response.redirect(url, 302);
});

router.get("/auth/github/callback", (request, env) => {
  return handleCallback("github", request, env, `${baseUrl(request)}/auth/github/callback`);
});

// --- OAuth: Google ---
router.get("/auth/google", async (request, env) => {
  const url = await buildAuthUrl("google", env, `${baseUrl(request)}/auth/google/callback`);
  if (!url) return json({ error: "Google not configured" }, 500);
  return Response.redirect(url, 302);
});

router.get("/auth/google/callback", (request, env) => {
  return handleCallback("google", request, env, `${baseUrl(request)}/auth/google/callback`);
});

// --- 获取当前用户 ---
router.get("/auth/user", (request) => {
  const { username, name, email, avatar, provider } = request.user;
  return json({ username, name, email, avatar, provider });
});

// --- 登出 ---
router.get("/auth/logout", (request, env) => {
  return buildLogoutResponse(env.USER_KV, request);
});

// --- 健康检查 ---
router.get("/health", () => new Response("OK", { status: 200 }));

// --- 404 ---
router.all("*", () => new Response("Not Found", { status: 404 }));

// ============================================================
// 入口
// ============================================================

export default {
  async fetch(request, env, ctx) {
    // 先执行鉴权中间件
    const redirect = await authGuard(request, env);
    if (redirect) return redirect;

    // 路由分发
    return router.fetch(request, env, ctx).catch((e) => {
      // authGuard 以外的异常
      return error(500, { error: "internal server error" });
    });
  },
};
