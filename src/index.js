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
  "/auth/wechat",
  "/auth/wechat/callback",
  "/auth/qq",
  "/auth/qq/callback",
  "/auth/logout",
  "/health"
]);

// ============================================================
// 鉴权中间件：非公开路由未登录 -> 302 /index.html
// ============================================================

async function authGuard(request, env) {
  // 白名单路径直接放行（登录页、回调、健康检查等）
  if (PUBLIC_PATHS.has(new URL(request.url).pathname)) return;

  const user = await getCurrentUser(request, env);
  // 未登录 → 重定向到首页
  if (!user) {
    return Response.redirect("/index.html", 302);
  }
  // 已登录 → 将用户信息挂载到 request，放行
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
  // 已登录 → 个人中心页面；未登录 → 登录页
  return request.user
    ? Response.redirect("/user.html", 302)
    : Response.redirect("/index.html", 302);
});

// --- 用户信息页（需登录） ---
router.get("/user", (request) => {
  const { username, name, email, avatar, provider } = request.user;
  return json({ username, name, email, avatar, provider });
});

// --- OAuth: GitHub ---
// GitHub OAuth 跳转示例：
// https://github.com/login/oauth/authorize
//   ?client_id=xxx
//   &redirect_uri=https://example.com/auth/github/callback
//   &response_type=code
//   &scope=read:user+user:email
//   &state=<random_32_chars>
router.get("/auth/github", async (request, env) => {
  const url = await buildAuthUrl("github", env, `${baseUrl(request)}/auth/github/callback`);
  if (!url) return json({ error: "GitHub not configured" }, 500);
  return Response.redirect(url, 302);
});

router.get("/auth/github/callback", (request, env) => {
  return handleCallback("github", request, env, `${baseUrl(request)}/auth/github/callback`);
});

// --- OAuth: Google ---
// Google OAuth 跳转示例：
// https://accounts.google.com/o/oauth2/v2/auth
//   ?client_id=xxx.apps.googleusercontent.com
//   &redirect_uri=https://example.com/auth/google/callback
//   &response_type=code
//   &scope=openid+email+profile
//   &state=<random_32_chars>
//   &code_challenge=<PKCE_challenge>
//   &code_challenge_method=S256
router.get("/auth/google", async (request, env) => {
  const url = await buildAuthUrl("google", env, `${baseUrl(request)}/auth/google/callback`);
  if (!url) return json({ error: "Google not configured" }, 500);
  return Response.redirect(url, 302);
});

router.get("/auth/google/callback", (request, env) => {
  return handleCallback("google", request, env, `${baseUrl(request)}/auth/google/callback`);
});

// --- OAuth: 微信网站应用扫码登录 ---
// 微信 OAuth 跳转示例：
// https://open.weixin.qq.com/connect/qrconnect
//   ?appid=APPID
//   &redirect_uri=https://example.com/auth/wechat/callback
//   &response_type=code
//   &scope=snsapi_login
//   &state=<random_32_chars>
//   #wechat_redirect
router.get("/auth/wechat", async (request, env) => {
  const url = await buildAuthUrl("wechat", env, `${baseUrl(request)}/auth/wechat/callback`);
  if (!url) return json({ error: "WeChat not configured" }, 500);
  return Response.redirect(url, 302);
});

router.get("/auth/wechat/callback", (request, env) => {
  return handleCallback("wechat", request, env, `${baseUrl(request)}/auth/wechat/callback`);
});

// --- OAuth: QQ互联 ---
// QQ OAuth 跳转示例：
// https://graph.qq.com/oauth2.0/authorize
//   ?response_type=code
//   &client_id=APPID
//   &redirect_uri=https://example.com/auth/qq/callback
//   &scope=get_user_info
//   &state=<random_32_chars>
router.get("/auth/qq", async (request, env) => {
  const url = await buildAuthUrl("qq", env, `${baseUrl(request)}/auth/qq/callback`);
  if (!url) return json({ error: "QQ not configured" }, 500);
  return Response.redirect(url, 302);
});

router.get("/auth/qq/callback", (request, env) => {
  return handleCallback("qq", request, env, `${baseUrl(request)}/auth/qq/callback`);
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
    // 如果返回响应对象，则直接返回
    if (redirect instanceof Response) return redirect;

    // 路由分发
    return router.fetch(request, env, ctx).catch((e) => {
      // authGuard 以外的异常
      return error(500, { error: "internal server error" });
    });
  },
};
