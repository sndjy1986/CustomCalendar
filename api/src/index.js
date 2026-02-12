export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return cors(env, new Response(null, { status: 204 }));
    }

    try {
      // Public
      if (url.pathname === "/health") {
        return cors(env, json({ ok: true, ts: Date.now() }));
      }

      // --- AUTH ---
      if (url.pathname === "/auth/bootstrap" && request.method === "POST") {
        return cors(env, await handleBootstrap(request, env));
      }

      if (url.pathname === "/auth/login" && request.method === "POST") {
        return cors(env, await handleLogin(request, env));
      }

      if (url.pathname === "/auth/logout" && request.method === "POST") {
        return cors(env, handleLogout(env));
      }

      if (url.pathname === "/auth/me" && request.method === "GET") {
        return cors(env, await handleMe(request, env));
      }

      // --- PROTECTED API ---
      if (url.pathname === "/calendars" && request.method === "GET") {
        const user = await requireAuth(request, env);

        const { results } = await env.DB.prepare(
          "SELECT id, name, color, created_at FROM calendars ORDER BY created_at DESC"
        ).all();

        return cors(
          env,
          json({ user: { id: user.sub, email: user.email }, calendars: results })
        );
      }

      if (url.pathname === "/calendars" && request.method === "POST") {
        const user = await requireAuth(request, env);
        const body = await safeJson(request);

        if (!body?.name) return cors(env, json({ error: "Name required" }, 400));

        const id = crypto.randomUUID();
        const color = body.color || "#000000";
        const now = Date.now();

        await env.DB.prepare(
          "INSERT INTO calendars (id, name, color, created_by, created_at) VALUES (?, ?, ?, ?, ?)"
        )
          .bind(id, body.name, color, user.sub, now)
          .run();

        return cors(env, json({ id, name: body.name, color, created_by: user.sub, created_at: now }));
      }

      return cors(env, new Response("Not Found", { status: 404 }));
    } catch (err) {
      // IMPORTANT: return 401 for auth errors, not 500
      if (err?.message === "unauthorized") {
        return cors(env, json({ error: "Unauthorized" }, 401));
      }
      return cors(env, json({ error: "Server error" }, 500));
    }
  },
};

/* =========================
   AUTH HANDLERS
========================= */

async function handleBootstrap(request, env) {
  const body = await safeJson(request);
  const token = body?.bootstrap_token;
  const email = body?.email?.toLow
