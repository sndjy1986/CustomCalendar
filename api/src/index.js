const BUILD_ID = "family-cal-worker-2026-02-12h";
const PBKDF2_ITERATIONS = 100000;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return cors(env, request, new Response(null, { status: 204 }));
    }

    try {
      if (url.pathname === "/debug/config") {
        const allowed = getAllowedOrigins(env);
        return cors(env, request, json({
          ok: true,
          build_id: BUILD_ID,
          request_origin: request.headers.get("Origin") || null,
          allowed_origins: Array.from(allowed),
          has_FRONTEND_ORIGIN: !!normalize(env.FRONTEND_ORIGIN),
          FRONTEND_ORIGIN_value: normalize(env.FRONTEND_ORIGIN) || null,
          has_JWT_SECRET: !!normalize(env.JWT_SECRET),
          has_BOOTSTRAP_TOKEN: !!normalize(env.BOOTSTRAP_TOKEN),
          has_DB_binding: !!env.DB,
          pbkdf2_iterations: PBKDF2_ITERATIONS,
          cookie_domain: normalize(env.COOKIE_DOMAIN) || null,
          cookie_samesite: normalize(env.COOKIE_SAMESITE) || "Lax",
        }));
      }

      if (url.pathname === "/health") {
        return cors(env, request, json({ ok: true, build_id: BUILD_ID, ts: Date.now() }));
      }

      // AUTH
      if (url.pathname === "/auth/bootstrap" && request.method === "POST") {
        return cors(env, request, await handleBootstrap(request, env));
      }
      if (url.pathname === "/auth/login" && request.method === "POST") {
        return cors(env, request, await handleLogin(request, env));
      }
      if (url.pathname === "/auth/logout" && request.method === "POST") {
        return cors(env, request, handleLogout(env));
      }
      if (url.pathname === "/auth/me" && request.method === "GET") {
        return cors(env, request, await handleMe(request, env));
      }

      // CALENDARS (protected)
      if (url.pathname === "/calendars" && request.method === "GET") {
        const user = await requireAuth(request, env);
        const { results } = await env.DB.prepare(
          "SELECT id, name, color, created_at FROM calendars ORDER BY created_at DESC"
        ).all();
        return cors(env, request, json({ user, calendars: results, build_id: BUILD_ID }));
      }

      if (url.pathname === "/calendars" && request.method === "POST") {
        const user = await requireAuth(request, env);
        const body = await safeJson(request);

        const name = normalize(body?.name);
        const color = normalize(body?.color) || "#3b82f6";
        if (!name) return cors(env, request, json({ error: "Name required", build_id: BUILD_ID }, 400));

        const id = crypto.randomUUID();
        const now = Date.now();

        await env.DB.prepare(
          "INSERT INTO calendars (id, name, color, created_by, created_at) VALUES (?, ?, ?, ?, ?)"
        ).bind(id, name, color, user.sub, now).run();

        return cors(env, request, json({ ok: true, id, build_id: BUILD_ID }));
      }

      // EVENTS (protected)
      if (url.pathname === "/events" && request.method === "GET") {
        const user = await requireAuth(request, env);

        const start = parseInt(url.searchParams.get("start") || "", 10);
        const end = parseInt(url.searchParams.get("end") || "", 10);
        const calendar_id = normalize(url.searchParams.get("calendar_id"));

        if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) {
          return cors(env, request, json({ error: "start/end (ms) required", build_id: BUILD_ID }, 400));
        }

        let stmt;
        if (calendar_id) {
          stmt = env.DB.prepare(
            `SELECT id, calendar_id, title, location, start_ts, end_ts, all_day, color, icon, notes, recurrence
             FROM events
             WHERE calendar_id = ?
               AND start_ts < ?
               AND end_ts > ?
             ORDER BY start_ts ASC`
          ).bind(calendar_id, end, start);
        } else {
          stmt = env.DB.prepare(
            `SELECT id, calendar_id, title, location, start_ts, end_ts, all_day, color, icon, notes, recurrence
             FROM events
             WHERE start_ts < ?
               AND end_ts > ?
             ORDER BY start_ts ASC`
          ).bind(end, start);
        }

        const { results } = await stmt.all();
        return cors(env, request, json({ ok: true, user, events: results, build_id: BUILD_ID }));
      }

      if (url.pathname === "/events" && request.method === "POST") {
        const user = await requireAuth(request, env);
        const body = await safeJson(request);

        const calendar_id = normalize(body?.calendar_id);
        const title = normalize(body?.title);
        const location = normalize(body?.location);
        const notes = normalize(body?.notes);
        const icon = normalize(body?.icon);
        const color = normalize(body?.color);
        const all_day = body?.all_day ? 1 : 0;

        const start_ts = Number(body?.start_ts);
        const end_ts = Number(body?.end_ts);

        let recurrence = null;
        if (body?.recurrence && typeof body.recurrence === "object") {
          recurrence = JSON.stringify(body.recurrence);
        } else if (typeof body?.recurrence === "string" && body.recurrence.trim()) {
          recurrence = body.recurrence.trim();
        }

        if (!calendar_id) return cors(env, request, json({ error: "calendar_id required", build_id: BUILD_ID }, 400));
        if (!title) return cors(env, request, json({ error: "title required", build_id: BUILD_ID }, 400));
        if (!Number.isFinite(start_ts) || !Number.isFinite(end_ts) || end_ts <= start_ts) {
          return cors(env, request, json({ error: "Invalid start_ts/end_ts (ms)", build_id: BUILD_ID }, 400));
        }

        const id = crypto.randomUUID();
        const now = Date.now();

        await env.DB.prepare(
          `INSERT INTO events
           (id, calendar_id, title, location, start_ts, end_ts, all_day, color, icon, notes, recurrence, created_by, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          id,
          calendar_id,
          title,
          location || null,
          start_ts,
          end_ts,
          all_day,
          color || null,
          icon || null,
          notes || null,
          recurrence || null,
          user.sub,
          now
        ).run();

        return cors(env, request, json({ ok: true, id, build_id: BUILD_ID }));
      }

      // ✅ UPDATE EVENT
      if (url.pathname.startsWith("/events/") && request.method === "PUT") {
        const user = await requireAuth(request, env);
        const id = url.pathname.split("/")[2] || "";
        const body = await safeJson(request);

        if (!id) return cors(env, request, json({ error: "id required", build_id: BUILD_ID }, 400));

        const calendar_id = normalize(body?.calendar_id);
        const title = normalize(body?.title);
        const location = normalize(body?.location);
        const notes = normalize(body?.notes);
        const icon = normalize(body?.icon);
        const color = normalize(body?.color);
        const all_day = body?.all_day ? 1 : 0;

        const start_ts = Number(body?.start_ts);
        const end_ts = Number(body?.end_ts);

        let recurrence = null;
        if (body?.recurrence && typeof body.recurrence === "object") {
          recurrence = JSON.stringify(body.recurrence);
        } else if (typeof body?.recurrence === "string" && body.recurrence.trim()) {
          recurrence = body.recurrence.trim();
        }

        if (!calendar_id) return cors(env, request, json({ error: "calendar_id required", build_id: BUILD_ID }, 400));
        if (!title) return cors(env, request, json({ error: "title required", build_id: BUILD_ID }, 400));
        if (!Number.isFinite(start_ts) || !Number.isFinite(end_ts) || end_ts <= start_ts) {
          return cors(env, request, json({ error: "Invalid start_ts/end_ts (ms)", build_id: BUILD_ID }, 400));
        }

        await env.DB.prepare(
          `UPDATE events
           SET calendar_id = ?, title = ?, location = ?, start_ts = ?, end_ts = ?, all_day = ?,
               color = ?, icon = ?, notes = ?, recurrence = ?
           WHERE id = ? AND created_by = ?`
        ).bind(
          calendar_id,
          title,
          location || null,
          start_ts,
          end_ts,
          all_day,
          color || null,
          icon || null,
          notes || null,
          recurrence || null,
          id,
          user.sub
        ).run();

        return cors(env, request, json({ ok: true, id, build_id: BUILD_ID }));
      }

      // ✅ DELETE EVENT
      if (url.pathname.startsWith("/events/") && request.method === "DELETE") {
        const user = await requireAuth(request, env);
        const id = url.pathname.split("/")[2] || "";

        if (!id) return cors(env, request, json({ error: "id required", build_id: BUILD_ID }, 400));

        await env.DB.prepare(
          "DELETE FROM events WHERE id = ? AND created_by = ?"
        ).bind(id, user.sub).run();

        return cors(env, request, json({ ok: true, build_id: BUILD_ID }));
      }

      return cors(env, request, new Response("Not Found", { status: 404 }));
    } catch (err) {
      if (err?.message === "unauthorized") {
        return cors(env, request, json({ error: "Unauthorized", build_id: BUILD_ID }, 401));
      }
      return cors(env, request, json({
        error: "Server error",
        build_id: BUILD_ID,
        details: String(err?.message || err),
      }, 500));
    }
  },
};

/* =======================
   CORS
======================= */

function cors(env, request, response) {
  const origin = request.headers.get("Origin") || "";
  const allowed = getAllowedOrigins(env);

  const headers = new Headers(response.headers);

  if (origin && allowed.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }

  headers.set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type");

  return new Response(response.body, { status: response.status, headers });
}

function getAllowedOrigins(env) {
  const set = new Set();
  set.add("https://cal.sndjy.us");

  const raw = normalize(env.FRONTEND_ORIGIN);
  if (raw) raw.split(",").map(s => s.trim()).filter(Boolean).forEach(o => set.add(o));
  return set;
}

/* =======================
   AUTH
======================= */

async function handleBootstrap(request, env) {
  const body = await safeJson(request);

  const expected = normalize(env.BOOTSTRAP_TOKEN);
  if (!expected) return json({ error: "BOOTSTRAP_TOKEN not configured", build_id: BUILD_ID }, 500);

  const provided = normalize(body?.bootstrap_token);
  if (provided !== expected) return json({ error: "Invalid bootstrap token", build_id: BUILD_ID }, 403);

  const email = normalize(body?.email).toLowerCase();
  const password = body?.password;

  if (!email || !password) return json({ error: "Email and password required", build_id: BUILD_ID }, 400);
  if (!env.DB) return json({ error: "DB binding missing", build_id: BUILD_ID }, 500);

  const existing = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
  if (existing?.c > 0) return json({ error: "Bootstrap already completed", build_id: BUILD_ID }, 409);

  const { saltB64, hashB64, iterations } = await hashPasswordPBKDF2(password, PBKDF2_ITERATIONS);

  const id = crypto.randomUUID();
  const now = Date.now();

  await env.DB.prepare(
    "INSERT INTO users (id, email, password_hash, salt, iterations, created_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(id, email, hashB64, saltB64, iterations, now).run();

  const jwt = await signJWT(env.JWT_SECRET, { sub: id, email });
  return withSessionCookie(env, json({ ok: true, email, build_id: BUILD_ID }), jwt);
}

async function handleLogin(request, env) {
  const body = await safeJson(request);

  const email = normalize(body?.email).toLowerCase();
  const password = body?.password;

  if (!email || !password) return json({ error: "Email and password required", build_id: BUILD_ID }, 400);
  if (!env.DB) return json({ error: "DB binding missing", build_id: BUILD_ID }, 500);

  const user = await env.DB.prepare(
    "SELECT id, email, password_hash, salt, iterations FROM users WHERE email = ?"
  ).bind(email).first();

  if (!user) return json({ error: "Invalid credentials", build_id: BUILD_ID }, 401);

  const ok = await verifyPasswordPBKDF2(password, user.salt, user.password_hash, user.iterations);
  if (!ok) return json({ error: "Invalid credentials", build_id: BUILD_ID }, 401);

  const jwt = await signJWT(env.JWT_SECRET, { sub: user.id, email: user.email });
  return withSessionCookie(env, json({ ok: true, email: user.email, build_id: BUILD_ID }), jwt);
}

async function handleMe(request, env) {
  const user = await getUser(request, env);
  if (!user) return json({ logged_in: false, build_id: BUILD_ID });
  return json({ logged_in: true, user, build_id: BUILD_ID });
}

function handleLogout(env) {
  return new Response(JSON.stringify({ ok: true, build_id: BUILD_ID }), {
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": buildSessionCookie(env, "", 0),
    },
  });
}

async function requireAuth(request, env) {
  const user = await getUser(request, env);
  if (!user) throw new Error("unauthorized");
  return user;
}

async function getUser(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const token = getCookie(cookie, "session");
  if (!token) return null;
  return await verifyJWT(env.JWT_SECRET, token);
}

/* =======================
   COOKIE HELPERS
======================= */

function withSessionCookie(env, response, jwt) {
  const headers = new Headers(response.headers);
  headers.set("Set-Cookie", buildSessionCookie(env, jwt, 60 * 60 * 24 * 14)); // 14 days
  return new Response(response.body, { status: response.status, headers });
}

function buildSessionCookie(env, value, maxAgeSeconds) {
  const domain = normalize(env.COOKIE_DOMAIN);
  const sameSite = normalize(env.COOKIE_SAMESITE) || "Lax";

  const parts = [
    `session=${encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    `SameSite=${sameSite}`,
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (domain) parts.push(`Domain=${domain}`);
  return parts.join("; ");
}

/* =======================
   PASSWORD (PBKDF2)
======================= */

async function hashPasswordPBKDF2(password, iterations) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    key,
    256
  );

  return {
    saltB64: base64urlEncode(salt),
    hashB64: base64urlEncode(new Uint8Array(bits)),
    iterations,
  };
}

async function verifyPasswordPBKDF2(password, saltB64, expectedHashB64, iterations) {
  const salt = base64urlDecode(saltB64);
  const expected = base64urlDecode(expectedHashB64);

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    key,
    256
  );

  const actual = new Uint8Array(bits);
  return timingSafeEqual(actual, expected);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/* =======================
   JWT (HS256 minimal)
======================= */

async function signJWT(secret, payload) {
  const s = normalize(secret);
  if (!s) throw new Error("JWT_SECRET missing");

  const header = base64urlEncode(new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const body = base64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const data = header + "." + body;

  const sig = await hmac(s, data);
  const sigB64 = base64urlEncode(sig);
  return data + "." + sigB64;
}

async function verifyJWT(secret, token) {
  const s = normalize(secret);
  if (!s) return null;

  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [h, p, sig] = parts;
  const data = h + "." + p;

  const expectedSig = base64urlEncode(await hmac(s, data));
  if (!timingSafeEqual(base64urlDecode(sig), base64urlDecode(expectedSig))) return null;

  try {
    const payloadJson = new TextDecoder().decode(base64urlDecode(p));
    return JSON.parse(payloadJson);
  } catch {
    return null;
  }
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return new Uint8Array(sig);
}

/* =======================
   HELPERS
======================= */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function safeJson(req) {
  try { return await req.json(); } catch { return null; }
}

function getCookie(cookie, name) {
  const parts = cookie.split(";").map(x => x.trim());
  for (const p of parts) {
    if (p.startsWith(name + "=")) return decodeURIComponent(p.slice(name.length + 1));
  }
  return null;
}

function normalize(v) {
  if (v === undefined || v === null) return "";
  return String(v).trim();
}

function base64urlEncode(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  const b64 = btoa(binary);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64urlDecode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);
  const binary = atob(s);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
