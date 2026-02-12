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
  const email = body?.email?.toLowerCase?.().trim();
  const password = body?.password;

  if (!token || token !== env.BOOTSTRAP_TOKEN) {
    return json({ error: "Invalid bootstrap token" }, 403);
  }
  if (!email || !password) {
    return json({ error: "Email and password required" }, 400);
  }
  if (!isValidEmail(email)) {
    return json({ error: "Invalid email" }, 400);
  }
  if (password.length < 8) {
    return json({ error: "Password must be at least 8 characters" }, 400);
  }

  const existingCount = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
  if (existingCount?.c > 0) {
    return json({ error: "Bootstrap already completed" }, 409);
  }

  const { saltB64, hashB64, iterations } = await hashPasswordPBKDF2(password);

  const id = crypto.randomUUID();
  const now = Date.now();

  await env.DB.prepare(
    "INSERT INTO users (id, email, password_hash, salt, iterations, created_at) VALUES (?, ?, ?, ?, ?, ?)"
  )
    .bind(id, email, hashB64, saltB64, iterations, now)
    .run();

  const jwt = await signJWT(env.JWT_SECRET, { sub: id, email }, 60 * 60 * 24 * 7);
  return withSessionCookie(env, json({ ok: true, email }), jwt);
}

async function handleLogin(request, env) {
  const body = await safeJson(request);
  const email = body?.email?.toLowerCase?.().trim();
  const password = body?.password;

  if (!email || !password) return json({ error: "Email and password required" }, 400);

  const user = await env.DB.prepare(
    "SELECT id, email, password_hash, salt, iterations FROM users WHERE email = ?"
  )
    .bind(email)
    .first();

  if (!user) return json({ error: "Invalid credentials" }, 401);

  const ok = await verifyPasswordPBKDF2(password, user.salt, user.password_hash, user.iterations);
  if (!ok) return json({ error: "Invalid credentials" }, 401);

  const jwt = await signJWT(env.JWT_SECRET, { sub: user.id, email: user.email }, 60 * 60 * 24 * 7);
  return withSessionCookie(env, json({ ok: true, email: user.email }), jwt);
}

function handleLogout(env) {
  return clearSessionCookie(env, json({ ok: true }));
}

async function handleMe(request, env) {
  const user = await getUserFromCookie(request, env);
  if (!user) return json({ logged_in: false });
  return json({ logged_in: true, user: { id: user.sub, email: user.email } });
}

/* =========================
   AUTH UTILITIES
========================= */

async function requireAuth(request, env) {
  const user = await getUserFromCookie(request, env);
  if (!user) throw new Error("unauthorized");
  return user;
}

async function getUserFromCookie(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const token = getCookie(cookie, "session");
  if (!token) return null;

  const payload = await verifyJWT(env.JWT_SECRET, token);
  if (!payload) return null;

  if (payload.exp && Date.now() / 1000 > payload.exp) return null;
  return payload;
}

function withSessionCookie(env, response, jwt) {
  const headers = new Headers(response.headers);
  headers.append("Set-Cookie", buildSessionCookie(env, jwt));
  return new Response(response.body, { status: response.status, headers });
}

function clearSessionCookie(env, response) {
  const headers = new Headers(response.headers);
  headers.append("Set-Cookie", buildSessionCookie(env, "", 0));
  return new Response(response.body, { status: response.status, headers });
}

function buildSessionCookie(env, value, maxAgeSeconds = 60 * 60 * 24 * 7) {
  const parts = [
    `session=${encodeURIComponent(value)}`,
    `Path=/`,
    `HttpOnly`,
    `Secure`,
    `SameSite=Lax`,
  ];
  parts.push(`Max-Age=${maxAgeSeconds}`);
  return parts.join("; ");
}

/* =========================
   PASSWORD HASHING (PBKDF2)
========================= */

async function hashPasswordPBKDF2(password) {
  const iterations = 210000;
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
  const hash = new Uint8Array(bits);
  return {
    saltB64: base64urlEncode(salt),
    hashB64: base64urlEncode(hash),
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

/* =========================
   JWT (HS256)
========================= */

async function signJWT(secret, payload, ttlSeconds) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);

  const fullPayload = { ...payload, iat: now, exp: now + ttlSeconds };

  const encHeader = base64urlEncode(new TextEncoder().encode(JSON.stringify(header)));
  const encPayload = base64urlEncode(new TextEncoder().encode(JSON.stringify(fullPayload)));
  const data = `${encHeader}.${encPayload}`;

  const sig = await hmacSHA256(secret, data);
  const encSig = base64urlEncode(sig);

  return `${data}.${encSig}`;
}

async function verifyJWT(secret, token) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [encHeader, encPayload, encSig] = parts;
  const data = `${encHeader}.${encPayload}`;

  const expectedSig = base64urlEncode(await hmacSHA256(secret, data));
  if (!timingSafeEqual(base64urlDecode(encSig), base64urlDecode(expectedSig))) return null;

  try {
    const payloadJson = new TextDecoder().decode(base64urlDecode(encPayload));
    return JSON.parse(payloadJson);
  } catch {
    return null;
  }
}

async function hmacSHA256(secret, data) {
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

/* =========================
   CORS + HELPERS
========================= */

function cors(env, response) {
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", env.FRONTEND_ORIGIN);
  headers.set("Access-Control-Allow-Credentials", "true");
  headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type");
  return new Response(response.body, { status: response.status, headers });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

async function safeJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function getCookie(cookieHeader, name) {
  const parts = cookieHeader.split(";").map((p) => p.trim());
  for (const part of parts) {
    if (part.startsWith(name + "=")) return decodeURIComponent(part.slice(name.length + 1));
  }
  return null;
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

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
