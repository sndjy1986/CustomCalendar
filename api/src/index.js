const BUILD_ID = "updated kids/api include calendar";
const PBKDF2_ITERATIONS = 100000;

/* =======================
   Worker
======================= */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = normalizePath(url.pathname);

    // CORS preflight
    if (request.method === "OPTIONS") {
      return cors(env, request, new Response(null, { status: 204 }));
    }

    try {
      /* =======================
         Debug/config
      ======================= */

      if (pathname === "/debug/config" && request.method === "GET") {
        const allowed = getAllowedOrigins(env);
        return cors(
          env,
          request,
          json({
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
          })
        );
      }

      /* =======================
         Health
      ======================= */

      if (pathname === "/health" && request.method === "GET") {
        return cors(env, request, json({ ok: true, build_id: BUILD_ID, ts: Date.now() }));
      }

      /* =======================
         AUTH (parent)
      ======================= */

      if (pathname === "/auth/bootstrap" && request.method === "POST") {
        return cors(env, request, await handleBootstrap(request, env));
      }
      if (pathname === "/auth/login" && request.method === "POST") {
        return cors(env, request, await handleLogin(request, env));
      }
      if (pathname === "/auth/logout" && request.method === "POST") {
        return cors(env, request, handleLogout(env));
      }
      if (pathname === "/auth/me" && request.method === "GET") {
        return cors(env, request, await handleMe(request, env));
      }

      /* =======================
         AUTH (kid)
      ======================= */

      if (pathname === "/kid/login" && request.method === "POST") {
        const body = await safeJson(request);
        const kid_id = normalize(body?.kid_id);
        const pin = normalize(body?.pin);

        if (!kid_id) {
          return cors(env, request, json({ error: "kid_id required", build_id: BUILD_ID }, 400));
        }
        if (!/^\d{4,8}$/.test(pin || "")) {
          return cors(env, request, json({ error: "pin must be 4-8 digits", build_id: BUILD_ID }, 400));
        }

        const kidRec = await env.DB.prepare(
          "SELECT id, name, created_by, pin_salt, pin_hash, pin_iterations, active FROM kids WHERE id = ?"
        ).bind(kid_id).first();

        if (!kidRec || kidRec.active === 0) {
          return cors(env, request, json({ error: "Invalid credentials", build_id: BUILD_ID }, 401));
        }
        if (!kidRec.pin_hash) {
          return cors(env, request, json({ error: "PIN not set for this kid", build_id: BUILD_ID }, 403));
        }

        const ok = await verifyPasswordPBKDF2(pin, kidRec.pin_salt, kidRec.pin_hash, kidRec.pin_iterations);
        if (!ok) {
          return cors(env, request, json({ error: "Invalid credentials", build_id: BUILD_ID }, 401));
        }

        const jwt = await signJWT(env.JWT_SECRET, {
          typ: "kid",
          kid_id: kidRec.id,
          parent_id: kidRec.created_by,
        });

        const res = json({ ok: true, build_id: BUILD_ID });
        const headers = new Headers(res.headers);
        headers.set("Set-Cookie", buildKidSessionCookie(env, jwt, 60 * 60 * 24 * 14)); // 14 days
        return cors(env, request, new Response(res.body, { status: res.status, headers }));
      }

      /* =======================
         CALENDARS (protected)
      ======================= */

      if (pathname === "/calendars" && request.method === "GET") {
        const user = await requireAuth(request, env);

        const { results } = await env.DB.prepare(
          "SELECT id, name, color, created_at FROM calendars WHERE created_by = ? ORDER BY created_at DESC"
        ).bind(user.sub).all();

        return cors(env, request, json({ ok: true, calendars: results, build_id: BUILD_ID }));
      }

      if (pathname === "/calendars" && request.method === "POST") {
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

      /* =======================
         EVENTS (protected)
      ======================= */

      if (pathname === "/events" && request.method === "GET") {
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
             WHERE created_by = ?
               AND calendar_id = ?
               AND start_ts < ?
               AND end_ts > ?
             ORDER BY start_ts ASC`
          ).bind(user.sub, calendar_id, end, start);
        } else {
          stmt = env.DB.prepare(
            `SELECT id, calendar_id, title, location, start_ts, end_ts, all_day, color, icon, notes, recurrence
             FROM events
             WHERE created_by = ?
               AND start_ts < ?
               AND end_ts > ?
             ORDER BY start_ts ASC`
          ).bind(user.sub, end, start);
        }

        const { results } = await stmt.all();
        return cors(env, request, json({ ok: true, events: results, build_id: BUILD_ID }));
      }

      if (pathname === "/events" && request.method === "POST") {
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

        // Ensure calendar belongs to user
        const cal = await env.DB.prepare(
          "SELECT id FROM calendars WHERE id = ? AND created_by = ?"
        ).bind(calendar_id, user.sub).first();
        if (!cal) return cors(env, request, json({ error: "Calendar not found", build_id: BUILD_ID }, 404));

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

      // UPDATE EVENT
      if (pathname.startsWith("/events/") && request.method === "PUT") {
        const user = await requireAuth(request, env);
        const id = pathname.split("/")[2] || "";
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

        const cal = await env.DB.prepare(
          "SELECT id FROM calendars WHERE id = ? AND created_by = ?"
        ).bind(calendar_id, user.sub).first();
        if (!cal) return cors(env, request, json({ error: "Calendar not found", build_id: BUILD_ID }, 404));

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

      // DELETE EVENT
      if (pathname.startsWith("/events/") && request.method === "DELETE") {
        const user = await requireAuth(request, env);
        const id = pathname.split("/")[2] || "";

        if (!id) return cors(env, request, json({ error: "id required", build_id: BUILD_ID }, 400));

        await env.DB.prepare(
          "DELETE FROM events WHERE id = ? AND created_by = ?"
        ).bind(id, user.sub).run();

        return cors(env, request, json({ ok: true, build_id: BUILD_ID }));
      }

      /* =======================
         KIDS (protected)
      ======================= */

      if (pathname === "/kids" && request.method === "GET") {
        const user = await requireAuth(request, env);

        const { results } = await env.DB.prepare(
          "SELECT id, name, avatar, calendar_id, created_at, updated_at FROM kids WHERE created_by = ? ORDER BY created_at DESC"
        ).bind(user.sub).all();

        return cors(env, request, json({ ok: true, kids: results, build_id: BUILD_ID }));
      }

      if (pathname === "/kids" && request.method === "POST") {
        const user = await requireAuth(request, env);
        const body = await safeJson(request);

        const name = normalize(body?.name);
        const avatar = normalize(body?.avatar);

        if (!name) return cors(env, request, json({ error: "name required", build_id: BUILD_ID }, 400));

        const id = crypto.randomUUID();
        const now = Date.now();

        // IMPORTANT: 7 columns => 7 placeholders
        await env.DB.prepare(
          "INSERT INTO kids (id, name, avatar, calendar_id, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
        ).bind(id, name, avatar || null, null, user.sub, now, now).run();

        return cors(env, request, json({ ok: true, id, build_id: BUILD_ID }));
      }

      if (/^\/kids\/[^/]+$/.test(pathname) && request.method === "PATCH") {
        const user = await requireAuth(request, env);
        const id = pathname.split("/")[2] || "";
        const body = await safeJson(request);

        if (!id) return cors(env, request, json({ error: "id required", build_id: BUILD_ID }, 400));

        const name = normalize(body?.name);
        const avatar = normalize(body?.avatar);
        const calendar_id = normalize(body?.calendar_id);
        const pin = normalize(body?.pin);

        if (!name) return cors(env, request, json({ error: "name required", build_id: BUILD_ID }, 400));
        if (pin && !/^\d{4,8}$/.test(pin)) {
          return cors(env, request, json({ error: "pin must be 4-8 digits", build_id: BUILD_ID }, 400));
        }

        const existing = await env.DB.prepare(
          "SELECT id FROM kids WHERE id = ? AND created_by = ?"
        ).bind(id, user.sub).first();

        if (!existing) return cors(env, request, json({ error: "Kid not found", build_id: BUILD_ID }, 404));

        // If calendar_id is set, verify it belongs to the parent
        if (calendar_id) {
          const cal = await env.DB.prepare(
            "SELECT id FROM calendars WHERE id = ? AND created_by = ?"
          ).bind(calendar_id, user.sub).first();
          if (!cal) return cors(env, request, json({ error: "Calendar not found", build_id: BUILD_ID }, 404));
        }

        let pin_salt = null, pin_hash = null, pin_iterations = null;
        if (pin) {
          const hashed = await hashPasswordPBKDF2(pin, PBKDF2_ITERATIONS);
          pin_salt = hashed.saltB64;
          pin_hash = hashed.hashB64;
          pin_iterations = hashed.iterations;
        }

        const now = Date.now();

        if (pin) {
          await env.DB.prepare(
            "UPDATE kids SET name=?, avatar=?, calendar_id=?, pin_salt=?, pin_hash=?, pin_iterations=?, updated_at=? WHERE id=? AND created_by=?"
          ).bind(
            name,
            avatar || null,
            calendar_id || null,
            pin_salt,
            pin_hash,
            pin_iterations,
            now,
            id,
            user.sub
          ).run();
        } else {
          await env.DB.prepare(
            "UPDATE kids SET name=?, avatar=?, calendar_id=?, updated_at=? WHERE id=? AND created_by=?"
          ).bind(
            name,
            avatar || null,
            calendar_id || null,
            now,
            id,
            user.sub
          ).run();
        }

        return cors(env, request, json({ ok: true, id, build_id: BUILD_ID }));
      }

      // Kid landing summary (protected)
      if (/^\/kids\/[^/]+\/landing$/.test(pathname) && request.method === "GET") {
        const user = await requireAuth(request, env);
        const id = pathname.split("/")[2] || "";

        if (!id) return cors(env, request, json({ error: "id required", build_id: BUILD_ID }, 400));

        const kid = await env.DB.prepare(
          "SELECT id, name FROM kids WHERE id = ? AND created_by = ?"
        ).bind(id, user.sub).first();

        if (!kid) return cors(env, request, json({ error: "Kid not found", build_id: BUILD_ID }, 404));

        const now = Date.now();
        const soon = now + (7 * 24 * 60 * 60 * 1000);

        const overdue = await env.DB.prepare(
          "SELECT COUNT(*) as c FROM chores WHERE kid_id = ? AND created_by = ? AND status = 'assigned' AND due_ts < ?"
        ).bind(id, user.sub, now).first();

        const dueSoon = await env.DB.prepare(
          "SELECT COUNT(*) as c FROM chores WHERE kid_id = ? AND created_by = ? AND status = 'assigned' AND due_ts >= ? AND due_ts <= ?"
        ).bind(id, user.sub, now, soon).first();

        const completed = await env.DB.prepare(
          "SELECT COUNT(*) as c FROM chores WHERE kid_id = ? AND created_by = ? AND status IN ('completed', 'rewarded')"
        ).bind(id, user.sub).first();

        const { results } = await env.DB.prepare(
          `SELECT id, title, status, due_ts
           FROM chores
           WHERE kid_id = ? AND created_by = ? AND status = 'assigned' AND due_ts <= ?
           ORDER BY due_ts ASC
           LIMIT 50`
        ).bind(id, user.sub, soon).all();

        return cors(env, request, json({
          ok: true,
          kid,
          summary: {
            overdue_count: Number(overdue?.c || 0),
            due_soon_count: Number(dueSoon?.c || 0),
            completed_count: Number(completed?.c || 0),
            due_chores: results,
          },
          build_id: BUILD_ID,
        }));
      }

      /* =======================
         KID EVENTS (kid auth)
      ======================= */

      if (pathname === "/kid/events" && request.method === "GET") {
        const kidAuth = await requireKidAuth(request, env);

        const start = parseInt(url.searchParams.get("start") || "", 10);
        const end = parseInt(url.searchParams.get("end") || "", 10);
        if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) {
          return cors(env, request, json({ error: "start/end required", build_id: BUILD_ID }, 400));
        }

        const kidRec = await env.DB.prepare(
          "SELECT calendar_id FROM kids WHERE id=? AND created_by=? AND active=1"
        ).bind(kidAuth.kid_id, kidAuth.parent_id).first();

        const calendar_id = kidRec?.calendar_id || null;
        if (!calendar_id) {
          return cors(env, request, json({ ok: true, calendar_id: null, events: [], build_id: BUILD_ID }));
        }

        const { results } = await env.DB.prepare(
          `SELECT id, calendar_id, title, location, start_ts, end_ts, all_day, color, icon, notes, recurrence
           FROM events
           WHERE created_by=? AND calendar_id=? AND start_ts < ? AND end_ts > ?
           ORDER BY start_ts ASC`
        ).bind(kidAuth.parent_id, calendar_id, end, start).all();

        return cors(env, request, json({ ok: true, calendar_id, events: results, build_id: BUILD_ID }));
      }

      /* =======================
         CHORES (protected)
      ======================= */

      if (pathname === "/chores" && request.method === "GET") {
        const user = await requireAuth(request, env);

        const kid_id = normalize(url.searchParams.get("kid_id"));
        const status = normalize(url.searchParams.get("status")).toLowerCase();
        const due_before_raw = normalize(url.searchParams.get("due_before"));
        const due_before = due_before_raw ? Number(due_before_raw) : null;

        if (due_before_raw && !Number.isFinite(due_before)) {
          return cors(env, request, json({ error: "due_before must be epoch ms", build_id: BUILD_ID }, 400));
        }
        if (status && !["assigned", "completed", "rewarded"].includes(status)) {
          return cors(env, request, json({ error: "invalid status", build_id: BUILD_ID }, 400));
        }

        const binds = [user.sub];
        const filters = ["c.created_by = ?"];

        if (kid_id) { filters.push("c.kid_id = ?"); binds.push(kid_id); }
        if (status) { filters.push("c.status = ?"); binds.push(status); }
        if (due_before !== null) { filters.push("c.due_ts <= ?"); binds.push(due_before); }

        const stmt = env.DB.prepare(
          `SELECT c.id, c.kid_id, c.title, c.description, c.status, c.due_ts, c.completed_at, c.rewarded_at, c.created_at
           FROM chores c
           INNER JOIN kids k ON k.id = c.kid_id
           WHERE ${filters.join(" AND ")} AND k.created_by = ?
           ORDER BY c.due_ts ASC, c.created_at DESC`
        ).bind(...binds, user.sub);

        const { results } = await stmt.all();
        return cors(env, request, json({ ok: true, chores: results, build_id: BUILD_ID }));
      }

      if (pathname === "/chores" && request.method === "POST") {
        const user = await requireAuth(request, env);
        const body = await safeJson(request);

        const kid_id = normalize(body?.kid_id);
        const title = normalize(body?.title);
        const description = normalize(body?.description);
        const due_ts = Number(body?.due_ts);

        if (!kid_id) return cors(env, request, json({ error: "kid_id required", build_id: BUILD_ID }, 400));
        if (!title) return cors(env, request, json({ error: "title required", build_id: BUILD_ID }, 400));
        if (!Number.isFinite(due_ts)) {
          return cors(env, request, json({ error: "due_ts required (epoch ms)", build_id: BUILD_ID }, 400));
        }

        const ownKid = await env.DB.prepare(
          "SELECT id FROM kids WHERE id = ? AND created_by = ?"
        ).bind(kid_id, user.sub).first();

        if (!ownKid) return cors(env, request, json({ error: "Kid not found", build_id: BUILD_ID }, 404));

        const id = crypto.randomUUID();
        const now = Date.now();

        await env.DB.prepare(
          `INSERT INTO chores (id, kid_id, title, description, status, due_ts, created_by, created_at, updated_at)
           VALUES (?, ?, ?, ?, 'assigned', ?, ?, ?, ?)`
        ).bind(id, kid_id, title, description || null, due_ts, user.sub, now, now).run();

        return cors(env, request, json({ ok: true, id, build_id: BUILD_ID }));
      }

      if (pathname.startsWith("/chores/") && request.method === "PUT") {
        const user = await requireAuth(request, env);
        const id = pathname.split("/")[2] || "";
        const body = await safeJson(request);
        const nextStatus = normalize(body?.status).toLowerCase();

        if (!id) return cors(env, request, json({ error: "id required", build_id: BUILD_ID }, 400));
        if (!["assigned", "completed", "rewarded"].includes(nextStatus)) {
          return cors(env, request, json({ error: "status must be assigned|completed|rewarded", build_id: BUILD_ID }, 400));
        }

        const chore = await env.DB.prepare(
          `SELECT c.id, c.status, c.kid_id
           FROM chores c
           INNER JOIN kids k ON k.id = c.kid_id
           WHERE c.id = ? AND c.created_by = ? AND k.created_by = ?`
        ).bind(id, user.sub, user.sub).first();

        if (!chore) return cors(env, request, json({ error: "Chore not found", build_id: BUILD_ID }, 404));

        const transitions = { assigned: "completed", completed: "rewarded", rewarded: null };
        if (transitions[chore.status] !== nextStatus) {
          return cors(env, request, json({ error: "Invalid status transition", build_id: BUILD_ID }, 409));
        }

        const now = Date.now();
        if (nextStatus === "completed") {
          await env.DB.prepare(
            "UPDATE chores SET status = ?, completed_at = ?, updated_at = ? WHERE id = ? AND created_by = ?"
          ).bind(nextStatus, now, now, id, user.sub).run();
        } else {
          await env.DB.prepare(
            "UPDATE chores SET status = ?, rewarded_at = ?, updated_at = ? WHERE id = ? AND created_by = ?"
          ).bind(nextStatus, now, now, id, user.sub).run();
        }

        return cors(env, request, json({ ok: true, id, status: nextStatus, build_id: BUILD_ID }));
      }

      /* =======================
         Gift cards + rewards (protected)
      ======================= */

      if (pathname === "/gift-cards" && request.method === "POST") {
        const user = await requireAuth(request, env);
        const body = await safeJson(request);

        const singleCode = normalize(body?.code);
        const manyCodes = Array.isArray(body?.codes)
          ? body.codes.map(x => normalize(x)).filter(Boolean)
          : [];
        const codes = [...manyCodes, ...(singleCode ? [singleCode] : [])];

        if (!codes.length) {
          return cors(env, request, json({ error: "code or codes[] required", build_id: BUILD_ID }, 400));
        }

        const now = Date.now();
        for (const code of codes) {
          const id = crypto.randomUUID();
          await env.DB.prepare(
            "INSERT INTO gift_cards (id, code, status, created_by, created_at) VALUES (?, ?, 'available', ?, ?)"
          ).bind(id, code, user.sub, now).run();
        }

        return cors(env, request, json({ ok: true, inserted: codes.length, build_id: BUILD_ID }));
      }

      if (pathname === "/rewards/issue" && request.method === "POST") {
        const user = await requireAuth(request, env);
        const body = await safeJson(request);

        const chore_id = normalize(body?.chore_id);
        const gift_card_id = normalize(body?.gift_card_id);
        if (!chore_id) return cors(env, request, json({ error: "chore_id required", build_id: BUILD_ID }, 400));

        const chore = await env.DB.prepare(
          `SELECT c.id, c.kid_id, c.status
           FROM chores c
           INNER JOIN kids k ON k.id = c.kid_id
           WHERE c.id = ? AND c.created_by = ? AND k.created_by = ?`
        ).bind(chore_id, user.sub, user.sub).first();

        if (!chore) return cors(env, request, json({ error: "Chore not found", build_id: BUILD_ID }, 404));
        if (chore.status !== "completed") {
          return cors(env, request, json({ error: "Chore must be completed before issuing reward", build_id: BUILD_ID }, 409));
        }

        let giftCard;
        if (gift_card_id) {
          giftCard = await env.DB.prepare(
            "SELECT id, status FROM gift_cards WHERE id = ? AND created_by = ?"
          ).bind(gift_card_id, user.sub).first();
        } else {
          giftCard = await env.DB.prepare(
            "SELECT id, status FROM gift_cards WHERE created_by = ? AND status = 'available' ORDER BY created_at ASC LIMIT 1"
          ).bind(user.sub).first();
        }

        if (!giftCard) return cors(env, request, json({ error: "No gift card available", build_id: BUILD_ID }, 404));
        if (giftCard.status !== "available") {
          return cors(env, request, json({ error: "Gift card unavailable", build_id: BUILD_ID }, 409));
        }

        const now = Date.now();

        await env.DB.prepare(
          "UPDATE gift_cards SET status = 'issued', issued_to_kid_id = ?, issued_for_chore_id = ?, issued_at = ? WHERE id = ? AND created_by = ?"
        ).bind(chore.kid_id, chore.id, now, giftCard.id, user.sub).run();

        await env.DB.prepare(
          "UPDATE chores SET status = 'rewarded', rewarded_at = ?, updated_at = ? WHERE id = ? AND created_by = ?"
        ).bind(now, now, chore.id, user.sub).run();

        return cors(env, request, json({ ok: true, chore_id: chore.id, gift_card_id: giftCard.id, build_id: BUILD_ID }));
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
   PATH NORMALIZATION
======================= */

function normalizePath(path) {
  if (!path) return "/";
  let trimmed = path.replace(/\/+$/, "");
  if (trimmed.startsWith("/api/")) trimmed = trimmed.slice(4);
  if (trimmed === "/api") trimmed = "/";
  return trimmed || "/";
}

/* =======================
   CORS
======================= */

function cors(env, request, response) {
  const origin = request.headers.get("Origin") || "";
  const headers = new Headers(response.headers);

  if (origin && isAllowedOrigin(env, origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }

  headers.set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, X-Bootstrap-Token");

  return new Response(response.body, { status: response.status, headers });
}

function getAllowedOrigins(env) {
  const set = new Set();
  set.add("https://cal.sndjy.us");

  const raw = normalize(env.FRONTEND_ORIGIN);
  if (raw) raw.split(",").map(s => s.trim()).filter(Boolean).forEach(o => set.add(o));
  return set;
}

function isAllowedOrigin(env, origin) {
  const allowed = getAllowedOrigins(env);
  if (allowed.has(origin)) return true;

  if (!origin.startsWith("https://")) return false;
  try {
    const { hostname } = new URL(origin);
    if (hostname === "customcalendar.pages.dev") return true;
    if (hostname.endsWith(".customcalendar.pages.dev")) return true;
  } catch (_) {
    return false;
  }
  return false;
}

/* =======================
   KID SESSION HELPERS
======================= */

async function getKid(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const token = getCookie(cookie, "kid_session");
  if (!token) return null;
  const payload = await verifyJWT(env.JWT_SECRET, token);
  if (!payload || payload.typ !== "kid") return null;
  return { kid_id: payload.kid_id, parent_id: payload.parent_id };
}

async function requireKidAuth(request, env) {
  const kid = await getKid(request, env);
  if (!kid) throw new Error("unauthorized");
  return kid;
}

function buildKidSessionCookie(env, value, maxAgeSeconds) {
  const domain = normalize(env.COOKIE_DOMAIN);
  const sameSite = normalize(env.COOKIE_SAMESITE) || "Lax";
  const parts = [
    `kid_session=${encodeURIComponent(value)}`,
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
   AUTH HANDLERS (parent)
======================= */

async function handleBootstrap(request, env) {
  const body = await safeJson(request);

  const expected = normalize(env.BOOTSTRAP_TOKEN);
  if (!expected) return json({ error: "BOOTSTRAP_TOKEN not configured", build_id: BUILD_ID }, 500);

  const providedHeader = normalize(request.headers.get("X-Bootstrap-Token"));
  const providedBody = normalize(body?.bootstrap_token);
  const provided = providedHeader || providedBody;

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
  headers.set("Set-Cookie", buildSessionCookie(env, jwt, 60 * 60 * 24 * 14));
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
