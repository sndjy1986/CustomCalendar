export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return json({ ok: true, ts: Date.now() });
    }

    if (url.pathname === "/calendars" && request.method === "GET") {
      const { results } = await env.DB.prepare(
        "SELECT id, name, color FROM calendars"
      ).all();

      return json(results);
    }

    if (url.pathname === "/calendars" && request.method === "POST") {
      const body = await request.json();

      if (!body.name) {
        return json({ error: "Name required" }, 400);
      }

      const id = crypto.randomUUID();
      const color = body.color || "#000000";

      await env.DB.prepare(
        "INSERT INTO calendars (id, name, color) VALUES (?, ?, ?)"
      )
        .bind(id, body.name, color)
        .run();

      return json({ id, name: body.name, color });
    }

    return new Response("Not Found", { status: 404 });
  },
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}
