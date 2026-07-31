export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 首页
    if (url.pathname === "/") {
      return new Response(
        JSON.stringify({
          message: "Welcome to Cloudflare Worker!",
          timestamp: new Date().toISOString(),
        }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // 注册：POST /register -> { username, password }
    if (url.pathname === "/register" && request.method === "POST") {
      try {
        const body = await request.json();
        const { username, password } = body;

        if (!username || !password) {
          return new Response(
            JSON.stringify({ error: "username and password are required" }),
            { status: 400, headers: { "Content-Type": "application/json" } }
          );
        }

        // 检查用户是否已存在
        const exists = await env.USER_KV.get(`user:${username}`);
        if (exists) {
          return new Response(
            JSON.stringify({ error: "user already exists" }),
            { status: 409, headers: { "Content-Type": "application/json" } }
          );
        }

        // 存储用户（生产环境请对密码做哈希处理）
        await env.USER_KV.put(`user:${username}`, password);
        return new Response(
          JSON.stringify({ message: "register success", username }),
          { status: 201, headers: { "Content-Type": "application/json" } }
        );
      } catch {
        return new Response(
          JSON.stringify({ error: "Invalid JSON" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }
    }

    // 登录：POST /login -> { username, password }
    if (url.pathname === "/login" && request.method === "POST") {
      try {
        const body = await request.json();
        const { username, password } = body;

        if (!username || !password) {
          return new Response(
            JSON.stringify({ error: "username and password are required" }),
            { status: 400, headers: { "Content-Type": "application/json" } }
          );
        }

        // 从 KV 中读取用户并验证密码
        const stored = await env.USER_KV.get(`user:${username}`);
        if (!stored || stored !== password) {
          return new Response(
            JSON.stringify({ error: "invalid username or password" }),
            { status: 401, headers: { "Content-Type": "application/json" } }
          );
        }

        return new Response(
          JSON.stringify({ message: "login success", username }),
          { headers: { "Content-Type": "application/json" } }
        );
      } catch {
        return new Response(
          JSON.stringify({ error: "Invalid JSON" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }
    }

    if (url.pathname === "/health") {
      return new Response("OK", { status: 200 });
    }

    return new Response("Not Found", { status: 404 });
  },
};
