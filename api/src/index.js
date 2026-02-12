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

  <!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Family Calendar</title>

  <!-- Material Design Icons -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@mdi/font@7.4.47/css/materialdesignicons.min.css">

  <style>
    :root{
      --bg:#0b0f14; --panel:#101826; --panel2:#0f172a;
      --text:#e5e7eb; --muted:#9ca3af; --line:#22314a; --accent:#60a5fa;
      --danger:#fb7185;
    }
    *{ box-sizing:border-box; }
    body{
      margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background:var(--bg); color:var(--text);
      min-height:100vh;
      display:grid;
      grid-template-columns: 320px 1fr;
    }
    aside{
      border-right:1px solid var(--line);
      padding:16px;
      background:linear-gradient(180deg, var(--panel), var(--bg));
    }
    main{
      padding:16px;
      display:flex;
      flex-direction:column;
      gap:12px;
    }

    .topbar{
      display:flex; align-items:center; justify-content:space-between; gap:12px;
      padding:12px;
      background:rgba(16,24,38,.75);
      border:1px solid var(--line);
      border-radius:14px;
    }
    .title{
      display:flex; align-items:center; gap:10px;
      font-weight:800;
    }
    .title i{ font-size:20px; color:var(--accent); }
    .nav{
      display:flex; align-items:center; gap:8px;
    }
    button{
      cursor:pointer;
      background:#0b1220;
      color:var(--text);
      border:1px solid var(--line);
      padding:10px 12px;
      border-radius:12px;
      font-weight:700;
    }
    button:hover{ border-color:#36507c; }
    .primary{
      background:var(--accent);
      color:#07111f;
      border-color:transparent;
    }
    .primary:hover{ filter:brightness(1.05); }
    .ghost{
      background:transparent;
    }

    .card{
      border:1px solid var(--line);
      background:rgba(15,23,42,.65);
      border-radius:14px;
      padding:12px;
    }
    .muted{ color:var(--muted); }
    .row{ display:flex; gap:10px; align-items:center; }
    .col{ display:flex; flex-direction:column; gap:10px; }

    /* Calendar grid */
    .dow{
      display:grid;
      grid-template-columns: repeat(7, 1fr);
      gap:8px;
      padding:0 2px;
      color:var(--muted);
      font-weight:800;
      letter-spacing:.04em;
      font-size:12px;
      text-transform:uppercase;
    }
    .grid{
      display:grid;
      grid-template-columns: repeat(7, 1fr);
      gap:8px;
    }
    .day{
      min-height:120px;
      border:1px solid var(--line);
      border-radius:14px;
      background:rgba(16,24,38,.55);
      padding:10px;
      display:flex;
      flex-direction:column;
      gap:8px;
      position:relative;
      overflow:hidden;
    }
    .day.outside{
      opacity:.55;
      background:rgba(16,24,38,.25);
    }
    .dayNum{
      display:flex; align-items:center; justify-content:space-between;
      font-weight:900;
    }
    .todayBadge{
      font-size:11px;
      padding:4px 8px;
      border-radius:999px;
      border:1px solid #2b4166;
      color:var(--accent);
      background:rgba(96,165,250,.08);
    }
    .events{
      display:flex;
      flex-direction:column;
      gap:6px;
      overflow:auto;
      padding-right:2px;
    }
    .evt{
      display:flex;
      align-items:center;
      gap:8px;
      padding:7px 8px;
      border-radius:12px;
      border:1px solid rgba(255,255,255,.08);
      background:rgba(2,6,23,.35);
      font-size:12px;
      line-height:1.2;
    }
    .evt i{ font-size:16px; opacity:.95; }
    .evt .t{ font-weight:800; }
    .evt .s{ color:var(--muted); font-weight:700; }
    .pill{
      width:10px; height:10px; border-radius:999px; flex:0 0 auto;
    }

    /* Sidebar calendars */
    .calItem{
      display:flex; align-items:center; justify-content:space-between;
      gap:10px;
      padding:10px;
      border:1px solid rgba(255,255,255,.06);
      border-radius:14px;
      background:rgba(2,6,23,.25);
    }
    .calLeft{ display:flex; align-items:center; gap:10px; }
    .swatch{ width:14px; height:14px; border-radius:6px; }
    .calName{ font-weight:900; }
    .tiny{ font-size:12px; color:var(--muted); font-weight:700; }

    input, select, textarea{
      width:100%;
      padding:10px 12px;
      border-radius:12px;
      border:1px solid var(--line);
      background:#0b1220;
      color:var(--text);
      outline:none;
    }
    textarea{ min-height:80px; resize:vertical; }
    label{ font-size:12px; font-weight:900; color:var(--muted); }

    .split{ display:grid; grid-template-columns: 1fr 1fr; gap:10px; }
    .split3{ display:grid; grid-template-columns: 1fr 1fr 1fr; gap:10px; }

    /* Modal */
    .modalWrap{
      position:fixed; inset:0; display:none;
      background:rgba(0,0,0,.6);
      align-items:center; justify-content:center;
      padding:16px;
    }
    .modal{
      width:min(720px, 100%);
      border:1px solid var(--line);
      background:rgba(15,23,42,.92);
      border-radius:18px;
      padding:14px;
      box-shadow: 0 20px 80px rgba(0,0,0,.5);
    }
    .modalHeader{
      display:flex; align-items:center; justify-content:space-between;
      gap:10px; margin-bottom:10px;
    }
    .modalHeader h2{ margin:0; font-size:16px; }
    .danger{ border-color:rgba(251,113,133,.35); color:#fecdd3; }
  </style>
</head>
<body>
  <aside>
    <div class="title" style="margin-bottom:12px;">
      <i class="mdi mdi-calendar-month"></i>
      <div>
        <div style="font-size:16px;">Family Calendar</div>
        <div class="tiny" id="who"></div>
      </div>
    </div>

    <div class="card col">
      <div class="row" style="justify-content:space-between;">
        <div style="font-weight:900;">Calendars</div>
        <button class="ghost" onclick="openCalendarModal()"><i class="mdi mdi-plus"></i></button>
      </div>
      <div id="calList" class="col"></div>
      <div class="tiny">Tip: events inherit calendar color unless you override it.</div>
    </div>

    <div style="height:12px;"></div>

    <div class="card col">
      <button class="primary" onclick="openEventModal()">
        <i class="mdi mdi-plus"></i> New event
      </button>
      <button class="danger" onclick="logout()">
        <i class="mdi mdi-logout"></i> Logout
      </button>
      <div class="tiny" id="status"></div>
    </div>
  </aside>

  <main>
    <div class="topbar">
      <div class="row" style="gap:12px;">
        <button class="ghost" onclick="goToday()"><i class="mdi mdi-target"></i> Today</button>
        <div style="font-weight:900; font-size:16px;" id="monthLabel">...</div>
      </div>
      <div class="nav">
        <button onclick="shiftMonth(-1)"><i class="mdi mdi-chevron-left"></i></button>
        <button onclick="shiftMonth(1)"><i class="mdi mdi-chevron-right"></i></button>
      </div>
    </div>

    <div class="dow">
      <div>Sun</div><div>Mon</div><div>Tue</div><div>Wed</div><div>Thu</div><div>Fri</div><div>Sat</div>
    </div>

    <div class="grid" id="grid"></div>
  </main>

  <!-- Calendar Modal -->
  <div class="modalWrap" id="calModalWrap" onclick="if(event.target.id==='calModalWrap') closeCalendarModal()">
    <div class="modal">
      <div class="modalHeader">
        <h2>Create Calendar</h2>
        <button class="ghost" onclick="closeCalendarModal()"><i class="mdi mdi-close"></i></button>
      </div>

      <div class="split">
        <div class="col">
          <label>Name</label>
          <input id="calName" placeholder="Arianna / Family / School..." />
        </div>
        <div class="col">
          <label>Color</label>
          <input id="calColor" type="color" value="#60a5fa" />
        </div>
      </div>

      <div class="row" style="justify-content:flex-end; margin-top:10px;">
        <button class="primary" onclick="createCalendar()">Create</button>
      </div>
    </div>
  </div>

  <!-- Event Modal -->
  <div class="modalWrap" id="evtModalWrap" onclick="if(event.target.id==='evtModalWrap') closeEventModal()">
    <div class="modal">
      <div class="modalHeader">
        <h2>New Event</h2>
        <button class="ghost" onclick="closeEventModal()"><i class="mdi mdi-close"></i></button>
      </div>

      <div class="split">
        <div class="col">
          <label>Calendar</label>
          <select id="evtCalendar"></select>
        </div>
        <div class="col">
          <label>Icon (MDI class)</label>
          <input id="evtIcon" placeholder="mdi-stethoscope" value="mdi-calendar" />
        </div>
      </div>

      <div class="col" style="margin-top:10px;">
        <label>Title</label>
        <input id="evtTitle" placeholder="Arianna Nurse Practitioner Appointment" />
      </div>

      <div class="col" style="margin-top:10px;">
        <label>Location</label>
        <input id="evtLocation" placeholder="100 Perpetual Square" />
      </div>

      <div class="split" style="margin-top:10px;">
        <div class="col">
          <label>Start</label>
          <input id="evtStart" type="datetime-local" />
        </div>
        <div class="col">
          <label>End</label>
          <input id="evtEnd" type="datetime-local" />
        </div>
      </div>

      <div class="split3" style="margin-top:10px;">
        <div class="col">
          <label>All day</label>
          <select id="evtAllDay">
            <option value="0">No</option>
            <option value="1">Yes</option>
          </select>
        </div>
        <div class="col">
          <label>Override color</label>
          <input id="evtColor" type="color" value="#000000" />
          <div class="tiny">Leave black to use calendar color.</div>
        </div>
        <div class="col">
          <label>Recurrence</label>
          <select id="evtRepeat">
            <option value="none">None</option>
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
            <option value="monthly">Monthly</option>
          </select>
        </div>
      </div>

      <div class="split3" style="margin-top:10px;">
        <div class="col">
          <label>Interval</label>
          <input id="evtInterval" type="number" min="1" value="1" />
        </div>
        <div class="col">
          <label>Until (optional)</label>
          <input id="evtUntil" type="date" />
        </div>
        <div class="col">
          <label>Count (optional)</label>
          <input id="evtCount" type="number" min="1" placeholder="e.g. 10" />
        </div>
      </div>

      <div class="col" style="margin-top:10px;">
        <label>Notes</label>
        <textarea id="evtNotes" placeholder="Anything helpful..."></textarea>
      </div>

      <div class="row" style="justify-content:flex-end; margin-top:10px;">
        <!-- FIXED: don't call the ancient DOM createEvent() -->
        <button class="primary" onclick="saveEvent()">Save Event</button>
      </div>
    </div>
  </div>

  <script>
    // ✅ Set your API base here
    const API = "https://api.cal.sndjy.us";

    // State
    let me = null;
    let calendars = [];
    let events = []; // raw events from API
    let viewDate = new Date(); // current month reference

    // ---------- Boot ----------
    (async function init(){
      await requireLogin();
      await loadCalendars();
      renderCalendarSelect();
      renderMonth();
      await loadEventsForVisibleMonth();
      renderMonth();
    })();

    async function requireLogin(){
      const res = await fetch(API + "/auth/me", { credentials: "include" });
      const data = await res.json();
      if (!data.logged_in) {
        location.href = "/login.html";
        return;
      }
      me = data.user;
      document.getElementById("who").textContent = me.email;
      setStatus("Logged in.");
    }

    // ---------- Calendars ----------
    async function loadCalendars(){
      const res = await fetch(API + "/calendars", { credentials: "include" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to load calendars");
      calendars = data.calendars || [];
      renderCalendarsSidebar();
    }

    function renderCalendarsSidebar(){
      const wrap = document.getElementById("calList");
      wrap.innerHTML = "";

      if (!calendars.length) {
        const d = document.createElement("div");
        d.className = "tiny";
        d.textContent = "No calendars yet. Add one.";
        wrap.appendChild(d);
        return;
      }

      for (const c of calendars) {
        const item = document.createElement("div");
        item.className = "calItem";
        item.innerHTML = `
          <div class="calLeft">
            <div class="swatch" style="background:${escapeHtml(c.color || "#60a5fa")}"></div>
            <div>
              <div class="calName">${escapeHtml(c.name)}</div>
              <div class="tiny">${new Date(c.created_at).toLocaleString()}</div>
            </div>
          </div>
        `;
        wrap.appendChild(item);
      }
    }

    function renderCalendarSelect(){
      const sel = document.getElementById("evtCalendar");
      sel.innerHTML = "";
      for (const c of calendars) {
        const opt = document.createElement("option");
        opt.value = c.id;
        opt.textContent = c.name;
        sel.appendChild(opt);
      }
    }

    function openCalendarModal(){
      document.getElementById("calModalWrap").style.display = "flex";
    }
    function closeCalendarModal(){
      document.getElementById("calModalWrap").style.display = "none";
    }

    async function createCalendar(){
      const name = document.getElementById("calName").value.trim();
      const color = document.getElementById("calColor").value;

      if (!name) { setStatus("Calendar name required.", true); return; }

      const res = await fetch(API + "/calendars", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ name, color })
      });
      const data = await res.json().catch(()=> ({}));
      if (!res.ok) { setStatus(data.error || "Failed to create calendar", true); return; }

      document.getElementById("calName").value = "";
      closeCalendarModal();
      await loadCalendars();
      renderCalendarSelect();
      await loadEventsForVisibleMonth();
      renderMonth();
      setStatus("Calendar created.");
    }

    // ---------- Month grid ----------
    function goToday(){
      viewDate = new Date();
      renderMonth();
      loadEventsForVisibleMonth().then(()=>renderMonth());
    }
    function shiftMonth(delta){
      viewDate = new Date(viewDate.getFullYear(), viewDate.getMonth() + delta, 1);
      renderMonth();
      loadEventsForVisibleMonth().then(()=>renderMonth());
    }

    function renderMonth(){
      const label = document.getElementById("monthLabel");
      label.textContent = viewDate.toLocaleString(undefined, { month:"long", year:"numeric" });

      const grid = document.getElementById("grid");
      grid.innerHTML = "";

      const firstOfMonth = new Date(viewDate.getFullYear(), viewDate.getMonth(), 1);
      const startDow = firstOfMonth.getDay();
      const start = new Date(firstOfMonth);
      start.setDate(firstOfMonth.getDate() - startDow);

      const today = new Date();
      const todayKey = keyYMD(today);

      for (let i = 0; i < 42; i++) {
        const d = new Date(start);
        d.setDate(start.getDate() + i);

        const outside = d.getMonth() !== viewDate.getMonth();
        const k = keyYMD(d);

        const cell = document.createElement("div");
        cell.className = "day" + (outside ? " outside" : "");
        cell.onclick = (e) => {
          if (e.target.closest(".evt")) return;
          openEventModal(d);
        };

        const head = document.createElement("div");
        head.className = "dayNum";
        head.innerHTML = `
          <div>${d.getDate()}</div>
          ${k === todayKey ? `<div class="todayBadge">Today</div>` : ``}
        `;

        const evts = document.createElement("div");
        evts.className = "events";

        const dayStart = new Date(d.getFullYear(), d.getMonth(), d.getDate(), 0,0,0,0).getTime();
        const dayEnd   = new Date(d.getFullYear(), d.getMonth(), d.getDate()+1, 0,0,0,0).getTime();

        const occ = expandEventsIntoRange(events, dayStart, dayEnd);
        const calById = new Map(calendars.map(c => [c.id, c]));

        occ.sort((a,b)=>a.start_ts-b.start_ts).slice(0, 6).forEach(o => {
          const cal = calById.get(o.calendar_id);
          const color = (o.color && o.color !== "#000000") ? o.color : (cal?.color || "#60a5fa");
          const icon = o.icon || "mdi-calendar";
          const timeLabel = o.all_day ? "All day" : formatTime(o.start_ts);

          const item = document.createElement("div");
          item.className = "evt";
          item.title = `${o.title}${o.location ? " @ " + o.location : ""}`;
          item.innerHTML = `
            <span class="pill" style="background:${escapeHtml(color)}"></span>
            <i class="mdi ${escapeHtml(icon)}"></i>
            <div style="min-width:0;">
              <div class="t" style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(o.title)}</div>
              <div class="s" style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
                ${escapeHtml(timeLabel)}${o.location ? " • " + escapeHtml(o.location) : ""}
              </div>
            </div>
          `;
          evts.appendChild(item);
        });

        cell.appendChild(head);
        cell.appendChild(evts);
        grid.appendChild(cell);
      }
    }

    async function loadEventsForVisibleMonth(){
      const firstOfMonth = new Date(viewDate.getFullYear(), viewDate.getMonth(), 1);
      const startDow = firstOfMonth.getDay();
      const start = new Date(firstOfMonth);
      start.setDate(firstOfMonth.getDate() - startDow);
      start.setHours(0,0,0,0);

      const end = new Date(start);
      end.setDate(start.getDate() + 42);
      end.setHours(0,0,0,0);

      const qs = new URLSearchParams({
        start: String(start.getTime()),
        end: String(end.getTime()),
      });

      const res = await fetch(API + "/events?" + qs.toString(), { credentials: "include" });
      const data = await res.json().catch(()=> ({}));
      if (!res.ok) {
        setStatus((data.details || data.error || "Failed to load events"), true);
        events = [];
        return;
      }
      events = data.events || [];
      setStatus("Events loaded.");
    }

    // ---------- Events ----------
    function openEventModal(date = null){
      if (!calendars.length) {
        setStatus("Create a calendar first.", true);
        openCalendarModal();
        return;
      }

      const now = new Date();
      const base = date ? new Date(date) : now;

      const start = new Date(base.getFullYear(), base.getMonth(), base.getDate(), 9, 0, 0, 0);
      const end = new Date(start.getTime() + 60*60*1000);

      document.getElementById("evtTitle").value = "";
      document.getElementById("evtLocation").value = "";
      document.getElementById("evtNotes").value = "";
      document.getElementById("evtIcon").value = "mdi-calendar";
      document.getElementById("evtAllDay").value = "0";
      document.getElementById("evtRepeat").value = "none";
      document.getElementById("evtInterval").value = "1";
      document.getElementById("evtUntil").value = "";
      document.getElementById("evtCount").value = "";
      document.getElementById("evtColor").value = "#000000";

      document.getElementById("evtStart").value = toLocalInput(start);
      document.getElementById("evtEnd").value = toLocalInput(end);

      document.getElementById("evtModalWrap").style.display = "flex";
    }
    function closeEventModal(){
      document.getElementById("evtModalWrap").style.display = "none";
    }

    // ✅ FIX: renamed from createEvent() to saveEvent()
    async function saveEvent(){
      const calendar_id = document.getElementById("evtCalendar").value;
      const title = document.getElementById("evtTitle").value.trim();
      const location = document.getElementById("evtLocation").value.trim();
      const notes = document.getElementById("evtNotes").value.trim();
      const icon = document.getElementById("evtIcon").value.trim();
      const all_day = document.getElementById("evtAllDay").value === "1";
      const color = document.getElementById("evtColor").value;

      const start = fromLocalInput(document.getElementById("evtStart").value);
      const end = fromLocalInput(document.getElementById("evtEnd").value);

      const repeat = document.getElementById("evtRepeat").value;
      const interval = parseInt(document.getElementById("evtInterval").value || "1", 10);
      const untilStr = document.getElementById("evtUntil").value;
      const countStr = document.getElementById("evtCount").value;

      if (!title) { setStatus("Title required.", true); return; }
      if (!start || !end || end <= start) { setStatus("Start/End invalid.", true); return; }

      let recurrence = null;
      if (repeat !== "none") {
        recurrence = {
          freq: repeat,
          interval: Number.isFinite(interval) && interval > 0 ? interval : 1,
          until: untilStr ? new Date(untilStr + "T23:59:59").getTime() : null,
          count: countStr ? Math.max(1, parseInt(countStr, 10)) : null
        };
      }

      const payload = {
        calendar_id,
        title,
        location: location || null,
        notes: notes || null,
        icon: icon || null,
        all_day,
        start_ts: start,
        end_ts: end,
        color: (color && color !== "#000000") ? color : null,
        recurrence
      };

      const res = await fetch(API + "/events", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(payload)
      });

      const data = await res.json().catch(()=> ({}));
      if (!res.ok) { setStatus(data.error || data.details || "Failed to save event", true); return; }

      closeEventModal();
      await loadEventsForVisibleMonth();
      renderMonth();
      setStatus("Event saved.");
    }

    function expandEventsIntoRange(raw, rangeStart, rangeEnd){
      const out = [];

      for (const e of raw) {
        if (!e.recurrence) {
          if (e.start_ts < rangeEnd && e.end_ts > rangeStart) out.push(e);
          continue;
        }

        let r = null;
        try { r = typeof e.recurrence === "string" ? JSON.parse(e.recurrence) : e.recurrence; } catch {}
        if (!r || !r.freq) {
          if (e.start_ts < rangeEnd && e.end_ts > rangeStart) out.push(e);
          continue;
        }

        const freq = r.freq;
        const interval = (Number(r.interval) > 0) ? Number(r.interval) : 1;
        const until = Number.isFinite(r.until) ? r.until : null;
        const count = Number.isFinite(r.count) ? r.count : null;

        let occStart = e.start_ts;
        let occEnd = e.end_ts;
        let n = 0;
        const HARD_CAP = 500;

        while (n < HARD_CAP) {
          if (occStart >= rangeEnd) break;
          if (until && occStart > until) break;
          if (count && n >= count) break;

          if (occStart < rangeEnd && occEnd > rangeStart) {
            out.push({ ...e, start_ts: occStart, end_ts: occEnd });
          }

          const s = new Date(occStart);
          const dur = occEnd - occStart;

          if (freq === "daily") s.setDate(s.getDate() + interval);
          else if (freq === "weekly") s.setDate(s.getDate() + (7 * interval));
          else if (freq === "monthly") s.setMonth(s.getMonth() + interval);
          else break;

          occStart = s.getTime();
          occEnd = occStart + dur;
          n++;
        }
      }

      return out;
    }

    // ---------- Logout ----------
    async function logout(){
      await fetch(API + "/auth/logout", { method:"POST", credentials:"include" });
      location.href = "/login.html";
    }

    // ---------- Helpers ----------
    function setStatus(msg, bad=false){
      const el = document.getElementById("status");
      el.textContent = msg;
      el.style.color = bad ? "var(--danger)" : "var(--muted)";
    }

    function toLocalInput(date){
      const pad = (n)=>String(n).padStart(2,"0");
      const y = date.getFullYear();
      const m = pad(date.getMonth()+1);
      const d = pad(date.getDate());
      const h = pad(date.getHours());
      const min = pad(date.getMinutes());
      return `${y}-${m}-${d}T${h}:${min}`;
    }

    function fromLocalInput(v){
      if (!v) return null;
      const d = new Date(v);
      return Number.isFinite(d.getTime()) ? d.getTime() : null;
    }

    function keyYMD(d){
      const pad = (n)=>String(n).padStart(2,"0");
      return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;
    }

    function formatTime(ts){
      const d = new Date(ts);
      return d.toLocaleTimeString([], { hour:"numeric", minute:"2-digit" });
    }

    function escapeHtml(s){
      return String(s ?? "").replace(/[&<>"']/g, c => ({
        "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
      }[c]));
    }
  </script>
</body>
</html>


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
