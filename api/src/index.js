const BUILD_ID = "nexus-v8-production";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // Normalize path: remove /api prefix and trailing slashes
    const pathname = url.pathname.replace(/\/+$/, "").replace(/^\/api/, "") || "/";

    // 1. Handle CORS Preflight
    if (request.method === "OPTIONS") {
      return handleCors(request, new Response(null, { status: 204 }));
    }

    try {
      /* =======================
         DEBUG: WHO AM I
      ======================= */
      // Use this to find your ADMIN_ID: https://calendar.sndjy.us/api/whoami
      if (pathname === "/whoami" && request.method === "GET") {
        const user = await getUser(request, env);
        return handleCors(request, json({ 
            logged_in: !!user, 
            id_string: user ? user.sub : "Not logged in",
            note: "Copy 'id_string' into your Cloudflare Environment Variables as ADMIN_ID"
        }));
      }

      /* =======================
         EVENTS: DASHBOARD ACCESS
      ======================= */
      if (pathname === "/events" && request.method === "GET") {
        let userSub = "";
        const apiKeyHeader = request.headers.get("x-api-key");
        const dashboardKey = env.DASHBOARD_API_KEY;

        // Check for API Key Bypass
        if (apiKeyHeader && dashboardKey && apiKeyHeader === dashboardKey) {
          userSub = env.ADMIN_ID; 
        } else {
          // Fallback to standard session check
          const user = await getUser(request, env);
          if (!user) throw new Error("unauthorized");
          userSub = user.sub;
        }

        // Get time range (default to 1 year window if not provided)
        const start = parseInt(url.searchParams.get("start") || "0");
        const end = parseInt(url.searchParams.get("end") || "2524608000000");

        // Query the D1 Database
        const { results } = await env.DB.prepare(
          "SELECT * FROM events WHERE created_by = ? AND start_ts >= ? AND start_ts <= ? ORDER BY start_ts ASC LIMIT 50"
        ).bind(userSub, start, end).all();

        return handleCors(request, json({ 
          ok: true, 
          events: results || [],
          debug_info: { user: userSub, count: (results || []).length }
        }));
      }

      /* =======================
         DEFAULT: 404
      ======================= */
      return handleCors(request, new Response("Nexus Protocol: Route Not Found", { status: 404 }));

    } catch (err) {
      const isAuthError = err.message === "unauthorized";
      return handleCors(request, json({ error: err.message, build: BUILD_ID }, isAuthError ? 401 : 500));
    }
  }
};

/* --- HELPER FUNCTIONS --- */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { 
    status, 
    headers: { "Content-Type": "application/json" } 
  });
}

function handleCors(request, response) {
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", request.headers.get("Origin") || "*");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, x-api-key, Authorization");
  headers.set("Access-Control-Allow-Credentials", "true");
  return new Response(response.body, { status: response.status, headers });
}

async function getUser(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const token = cookie.split('; ').find(row => row.startsWith('session='))?.split('=')[1];
  if (!token) return null;
  try {
    // Standard JWT decode for Cloudflare D1 Auth patterns
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return payload;
  } catch { return null; }
}

