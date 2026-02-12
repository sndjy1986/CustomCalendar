export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return cors(env, new Response(null, { status: 204 }));
    }

    try {
      // Public
      if (url.pathname === "/health") {
        return cors(env, json({ ok: true, ts: Date.now() }));
      }

      // AUTH
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

      // PROTECTED: calendars
      if (url.pathname === "/calendars" && request.method === "GET") {
        const user = await requireAuth(request, env);

        const { results } = await env.DB.prepare(
          "SELECT id, name, color, created_at FROM calendars ORDER BY created_at DESC"
        ).all();

        return cors(env, json({ user: { id: user.sub, email: user.email }, calendars: results }));
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
        ).bind(id, body.name, color, user.sub, now).run();

        return cors(env, json({ id, name: body.name, color, created_by: user.sub, created_at: now }));
      }

      // PROTECTED: events
      if (url.pathname === "/events" && request.method === "GET") {
        const user = await requireAuth(request, env);

        const calendarId = url.searchParams.get("calendar_id");
        const from = parseInt(url.searchParams.get("from") || "0", 10);
        const to = parseInt(url.searchParams.get("to") || "0", 10);
        const expand = url.searchParams.get("expand") === "1";

        if (!calendarId) return cors(env, json({ error: "calendar_id required" }, 400));
        if (!from || !to || to <= from) {
          return cors(env, json({ error: "Valid from/to required (epoch ms)" }, 400));
        }

        // Fetch events that *might* overlap range, including recurring
        // For non-recurring, we can filter by overlap.
        // For recurring, we include and expand.
        const { results } = await env.DB.prepare(
          `SELECT id, calendar_id, title, location, icon, start_ts, end_ts, all_day, rrule, created_at
           FROM events
           WHERE calendar_id = ?
           AND (
             rrule IS NOT NULL
             OR (start_ts < ? AND end_ts > ?)
             OR (start_ts >= ? AND start_ts <= ?)
             OR (end_ts >= ? AND end_ts <= ?)
           )
           ORDER BY start_ts ASC`
        )
          .bind(calendarId, to, from, from, to, from, to)
          .all();

        if (!expand) {
          return cors(env, json({ user: { id: user.sub, email: user.email }, events: results }));
        }

        const occurrences = [];
        for (const ev of results) {
          if (!ev.rrule) {
            // single event occurrence
            occurrences.push({
              occurrence_id: ev.id + "::" + ev.start_ts,
              event_id: ev.id,
              calendar_id: ev.calendar_id,
              title: ev.title,
              location: ev.location,
              icon: ev.icon,
              start_ts: ev.start_ts,
              end_ts: ev.end_ts,
              all_day: !!ev.all_day,
              rrule: null,
            });
          } else {
            // expand recurring
            const occs = expandRecurring(ev, from, to, 500);
            for (const o of occs) occurrences.push(o);
          }
        }

        // sort occurrences by start
        occurrences.sort((a, b) => a.start_ts - b.start_ts);

        return cors(
          env,
          json({
            user: { id: user.sub, email: user.email },
            events: results,
            occurrences,
          })
        );
      }

      if (url.pathname === "/events" && request.method === "POST") {
        const user = await requireAuth(request, env);
        const body = await safeJson(request);

        const calendar_id = body?.calendar_id;
        const title = body?.title?.trim();
        const location = (body?.location || "").trim() || null;
        const icon = (body?.icon || "").trim() || null;
        const start_ts = Number(body?.start_ts);
        const end_ts = Number(body?.end_ts);
        const all_day = body?.all_day ? 1 : 0;
        const rrule = (body?.rrule || "").trim() || null;

        if (!calendar_id) return cors(env, json({ error: "calendar_id required" }, 400));
        if (!title) return cors(env, json({ error: "title required" }, 400));
        if (!Number.isFinite(start_ts) || !Number.isFinite(end_ts) || end_ts <= start_ts) {
          return cors(env, json({ error: "Valid start_ts/end_ts required (epoch ms)" }, 400));
        }

        if (rrule && !isReasonableRRule(rrule)) {
          return cors(env, json({ error: "Invalid or unsupported rrule" }, 400));
        }

        const id = crypto.randomUUID();
        const now = Date.now();

        await env.DB.prepare(
          `INSERT INTO events
           (id, calendar_id, title, location, icon, start_ts, end_ts, all_day, rrule, created_by, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(id, calendar_id, title, location, icon, start_ts, end_ts, all_day, rrule, user.sub, now)
          .run();

        return cors(
          env,
          json({
            id,
            calendar_id,
            title,
            location,
            icon,
            start_ts,
            end_ts,
            all_day: !!all_day,
            rrule,
            created_at: now,
          })
        );
      }

      if (url.pathname === "/events" && request.method === "DELETE") {
        const user = await requireAuth(request, env);
        const body = await safeJson(request);
        const id = body?.id;

        if (!id) return cors(env, json({ error: "id required" }, 400));

        // Basic safety: only delete events created_by this user (for now)
        const res = await env.DB.prepare(
          "DELETE FROM events WHERE id = ? AND created_by = ?"
        ).bind(id, user.sub).run();

        // D1 returns changes sometimes, but keep it simple
        return cors(env, json({ ok: true }));
      }

      return cors(env, new Response("Not Found", { status: 404 }));
    } catch (err) {
      if (err?.message === "unauthorized") {
        return cors(env, json({ error: "Unauthorized" }, 401));
      }
      return cors(env, json({ error: "Server error" }, 500));
    }
  },
};

/* =========================
   Recurrence expansion
   Supports:
   - FREQ=DAILY|WEEKLY|MONTHLY
   - INTERVAL=n
   - BYDAY=MO,TU,WE,TH,FR,SA,SU (weekly)
   - COUNT=n
   - UNTIL=YYYYMMDDTHHMMSSZ (UTC) or YYYYMMDD
========================= */

function expandRecurring(ev, from, to, max = 500) {
  const rule = parseRRule(ev.rrule);
  if (!rule || !rule.FREQ) return [];

  const freq = rule.FREQ;
  const interval = parseInt(rule.INTERVAL || "1", 10) || 1;
  const countLimit = rule.COUNT ? Math.max(0, parseInt(rule.COUNT, 10) || 0) : null;
  const untilTs = rule.UNTIL ? parseUntil(rule.UNTIL) : null;

  const duration = ev.end_ts - ev.start_ts;
  const baseStart = ev.start_ts;

  const occurrences = [];
  let generated = 0;

  // We'll generate occurrences in an inclusive window, capped.
  // Strategy:
  // - For DAILY/MONTHLY: step by interval
  // - For WEEKLY: step by weeks, emit BYDAY set (or same weekday as base if BYDAY missing)

  if (freq === "DAILY") {
    // Start at first occurrence that could overlap 'from'
    let cursor = baseStart;

    if (cursor < from) {
      const diffDays = Math.floor((from - cursor) / DAY_MS);
      const step = diffDays - (diffDays % interval);
      cursor += step * DAY_MS;
      while (cursor + duration < from) cursor += interval * DAY_MS;
    }

    while (cursor < to && occurrences.length < max) {
      if (untilTs && cursor > untilTs) break;
      generated++;
      if (countLimit && generated > countLimit) break;

      const end = cursor + duration;
      if (end > from && cursor < to) {
        occurrences.push(makeOcc(ev, cursor, end));
      }
      cursor += interval * DAY_MS;
    }
  }

  if (freq === "WEEKLY") {
    const byday = (rule.BYDAY || "")
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);

    const days = byday.length ? byday : [weekdayToByday(new Date(baseStart).getDay())];
    const dayOffsets = days.map(bydayToOffsetFromSunday).filter((x) => x !== null);

    // Move cursor to beginning of base week (Sunday 00:00 local-ish)
    // We'll treat timestamps in ms and compute week starts in local time.
    let cursorWeekStart = startOfWeekLocal(baseStart);

    // Jump near the 'from' window
    while (cursorWeekStart + 7 * DAY_MS < from) {
      cursorWeekStart += interval * 7 * DAY_MS;
    }
    // Ensure we didn't undershoot too far
    while (cursorWeekStart > from) {
      cursorWeekStart -= interval * 7 * DAY_MS;
      if (cursorWeekStart < baseStart) break;
    }

    // Determine time-of-day for the event in local time
    const baseDate = new Date(baseStart);
    const baseH = baseDate.getHours();
    const baseM = baseDate.getMinutes();
    const baseS = baseDate.getSeconds();
    const baseMs = baseDate.getMilliseconds();

    // Generate week by week
    let weekCursor = cursorWeekStart;
    while (weekCursor < to && occurrences.length < max) {
      // for each day in BYDAY, create occurrence on that weekday with base time
      for (const off of dayOffsets) {
        const d = new Date(weekCursor + off * DAY_MS);
        d.setHours(baseH, baseM, baseS, baseMs);
        const start = d.getTime();

        if (start < baseStart) continue; // don't create occurrences before original start
        if (untilTs && start > untilTs) continue;

        generated++;
        if (countLimit && generated > countLimit) break;

        const end = start + duration;
        if (end > from && start < to) {
          occurrences.push(makeOcc(ev, start, end));
        }
        if (occurrences.length >= max) break;
      }

      if (countLimit && generated >= countLimit) break;
      weekCursor += interval * 7 * DAY_MS;
      if (untilTs && weekCursor > untilTs + 7 * DAY_MS) break;
    }
  }

  if (freq === "MONTHLY") {
    let cursor = new Date(baseStart);

    // Jump near from
    if (cursor.getTime() < from) {
      // estimate months diff
      const start = new Date(baseStart);
      const fromD = new Date(from);
      let months =
        (fromD.getFullYear() - start.getFullYear()) * 12 +
        (fromD.getMonth() - start.getMonth());
      months = months - (months % interval);
      cursor = addMonthsLocal(start, months);
      while (cursor.getTime() + duration < from) {
        cursor = addMonthsLocal(cursor, interval);
      }
    }

    while (cursor.getTime() < to && occurrences.length < max) {
      const start = cursor.getTime();
      if (start < baseStart) {
        cursor = addMonthsLocal(cursor, interval);
        continue;
      }
      if (untilTs && start > untilTs) break;

      generated++;
      if (countLimit && generated > countLimit) break;

      const end = start + duration;
      if (end > from && start < to) {
        occurrences.push(makeOcc(ev, start, end));
      }
      cursor = addMonthsLocal(cursor, interval);
    }
  }

  return occurrences.slice(0, max);
}

function makeOcc(ev, start_ts, end_ts) {
  return {
    occurrence_id: ev.id + "::" + start_ts,
    event_id: ev.id,
    calendar_id: ev.calendar_id,
    title: ev.title,
    location: ev.location,
    icon: ev.icon,
    start_ts,
    end_ts,
    all_day: !!ev.all_day,
    rrule: ev.rrule,
  };
}

function parseRRule(rrule) {
  if (!rrule || typeof rrule !== "string") return null;
  const obj = {};
  for (const part of rrule.split(";")) {
    const [k, v] = part.split("=");
    if (!k || v == null) continue;
    obj[k.trim().toUpperCase()] = v.trim().toUpperCase();
  }
  return obj;
}

function isReasonableRRule(rrule) {
  const r = parseRRule(rrule);
  if (!r || !r.FREQ) return false;
  if (!["DAILY", "WEEKLY", "MONTHLY"].includes(r.FREQ)) return false;
  if (r.INTERVAL && (!/^\d+$/.test(r.INTERVAL) || parseInt(r.INTERVAL, 10) <= 0)) return false;
  if (r.COUNT && (!/^\d+$/.test(r.COUNT) || parseInt(r.COUNT, 10) <= 0)) return false;
  if (r.UNTIL && !/^\d{8}(T\d{6}Z)?$/.test(r.UNTIL)) return false;
  if (r.BYDAY && !/^((MO|TU|WE|TH|FR|SA|SU),)*(MO|TU|WE|TH|FR|SA|SU)$/.test(r.BYDAY)) return false;
  return true;
}

function parseUntil(until) {
  // UNTIL=YYYYMMDD or YYYYMMDDTHHMMSSZ
  if (/^\d{8}$/.test(until)) {
    const y = parseInt(until.slice(0, 4), 10);
    const m = parseInt(until.slice(4, 6), 10) - 1;
    const d = parseInt(until.slice(6, 8), 10);
    // end of day local
    const dt = new Date(y, m, d, 23, 59, 59, 999);
    return dt.getTime();
  }
  if (/^\d{8}T\d{6}Z$/.test(until)) {
    const y = parseInt(until.slice(0, 4), 10);
    const m = parseInt(until.slice(4, 6), 10) - 1;
    const d = parseInt(until.slice(6, 8), 10);
    const hh = parseInt(until.slice(9, 11), 10);
    const mm = parseInt(until.slice(11, 13), 10);
    const ss = parseInt(until.slice(13, 15), 10);
    return Date.UTC(y, m, d, hh, mm, ss, 0);
  }
  return null;
}

const DAY_MS = 24 * 60 * 60 * 1000;

function startOfWeekLocal(ts) {
  const d = new Date(ts);
  const day = d.getDay(); // 0=Sun
  d.setHours(0, 0, 0, 0);
  d.setDate(d.getDate() - day);
  return d.getTime();
}

function addMonthsLocal(dateOrTs, months) {
  const d = dateOrTs instanceof Date ? new Date(dateOrTs.getTime()) : new Date(dateOrTs);
  const day = d.getDate();
  d.setDate(1);
  d.setMonth(d.getMonth() + months);
  // clamp day to last day of month
  const last = new Date(d.getFullYear(), d.getMonth() + 1, 0).getDate();
  d.setDate(Math.min(day, last));
  return d;
}

function weekdayToByday(jsDay) {
  return ["SU", "MO", "TU", "WE", "TH", "FR", "SA"][jsDay] || "MO";
}

function bydayToOffsetFromSunday(code) {
  const map = { SU: 0, MO: 1, TU: 2, WE: 3, TH: 4, FR: 5, SA: 6 };
  return map[code] ?? null;
}

/* =========================
   AUTH (same as before)
========================= */

async function handleBootstrap(request, env) {
  const body = await safeJson(request);
  const token = body?.bootstrap_token;
  const email = body?.email?.toLowerCase?.().trim();
  const password = body?.password;

  if (!token || token !== env.BOOTSTRAP_TOKEN) return json({ error: "Invalid bootstrap token" }, 403);
  if (!email || !password) return json({ error: "Email and password required" }, 400);
  if (!isValidEmail(email)) return json({ error: "Invalid email" }, 400);
  if (password.length < 8) return json({ error: "Password must be at least 8 characters" }, 400);

  const existingCount = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
  if (existingCount?.c > 0) return json({ error: "Bootstrap already completed" }, 409);

  const { saltB64, hashB64, iterations } = await hashPasswordPBKDF2(password);

  const id = crypto.randomUUID();
  const now = Date.now();

  await env.DB.prepare(
    "INSERT INTO users (id, email, password_hash, salt, iterations, created_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(id, email, hashB64, saltB64, iterations, now).run();

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
  ).bind(email).first();

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
  headers.append("Set-Cookie", buildSessionCookie(jwt));
  return new Response(response.body, { status: response.status, headers });
}

function clearSessionCookie(env, response) {
  const headers = new Headers(response.headers);
  headers.append("Set-Cookie", buildSessionCookie("", 0));
  return new Response(response.body, { status: response.status, headers });
}

function buildSessionCookie(value, maxAgeSeconds = 60 * 60 * 24 * 7) {
  const parts = [
    `session=${encodeURIComponent(value)}`,
    `Path=/`,
    `HttpOnly`,
    `Secure`,
    `SameSite=Lax`,
    `Max-Age=${maxAgeSeconds}`,
  ];
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
  headers.set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
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
