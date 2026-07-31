import {
  buildAuthUrl,
  handleCallback,
  buildLogoutResponse,
  getCurrentUser,
} from "./auth.js";

// ---------- 工具函数 ----------

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function getBaseUrl(request) {
  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
}

// ---------- 无需登录的公开路由 ----------

const PUBLIC_PATHS = new Set([
  "/auth/github",
  "/auth/github/callback",
  "/auth/google",
  "/auth/google/callback",
  "/auth/logout",
  "/health",
]);

/**
 * 统一鉴权守卫：非公开路由 -> 未登录则 302 到 /index.html
 * 返回用户对象，已登录则继续，未登录则直接抛出重定向响应
 */
async function requireAuth(request, env) {
  const url = new URL(request.url);

  // 公开路由或静态资源直接放行
  if (PUBLIC_PATHS.has(url.pathname)) return null;

  const user = await getCurrentUser(request, env);
  if (user) return user;

  // 未登录，302 到登录页
  throw Response.redirect("/index.html", 302);
}

// ---------- 路由处理 ----------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const baseUrl = getBaseUrl(request);

    try {
      // =====================================================
      // 首页
      // =====================================================
      if (url.pathname === "/") {
        const user = await requireAuth(request, env);
        return user
          ? Response.redirect("/user", 302)
          : null; // 未登录已在 requireAuth 中跳转
      }

      // =====================================================
      // 用户信息页（需登录）
      // =====================================================
      if (url.pathname === "/user") {
        const user = await requireAuth(request, env);
        return json({
          username: user.username,
          name: user.name,
          email: user.email,
          avatar: user.avatar,
          provider: user.provider,
        });
      }

      // =====================================================
      // OAuth: GitHub
      // =====================================================
      if (url.pathname === "/auth/github") {
        const authUrl = await buildAuthUrl("github", env, `${baseUrl}/auth/github/callback`);
        if (!authUrl) return json({ error: "provider not configured" }, 500);
        return Response.redirect(authUrl, 302);
      }
      if (url.pathname === "/auth/github/callback") {
        return handleCallback("github", request, env, `${baseUrl}/auth/github/callback`);
      }

      // =====================================================
      // OAuth: Google
      // =====================================================
      if (url.pathname === "/auth/google") {
        const authUrl = await buildAuthUrl("google", env, `${baseUrl}/auth/google/callback`);
        if (!authUrl) return json({ error: "provider not configured" }, 500);
        return Response.redirect(authUrl, 302);
      }
      if (url.pathname === "/auth/google/callback") {
        return handleCallback("google", request, env, `${baseUrl}/auth/google/callback`);
      }

      // =====================================================
      // 获取当前用户信息
      // =====================================================
      if (url.pathname === "/auth/user") {
        const user = await requireAuth(request, env);
        return json({
          username: user.username,
          name: user.name,
          email: user.email,
          avatar: user.avatar,
          provider: user.provider,
        });
      }

      // =====================================================
      // 登出
      // =====================================================
      if (url.pathname === "/auth/logout") {
        return buildLogoutResponse(env.USER_KV, request);
      }

      // =====================================================
      // 健康检查
      // =====================================================
      if (url.pathname === "/health") {
        return new Response("OK", { status: 200 });
      }

      return new Response("Not Found", { status: 404 });
    } catch (e) {
      // requireAuth 通过 throw Response 来中断流程（重定向）
      if (e instanceof Response) return e;
      return json({ error: "internal server error" }, 500);
    }
  },
};
