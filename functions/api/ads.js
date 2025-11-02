export async function onRequest(context) {
  const { request, env } = context;
  const db = env.DB;

  if (request.method === "GET") {
    // Return all ads
    const { results } = await db.prepare("SELECT * FROM ads ORDER BY id DESC").all();
    return Response.json(results);
  }

  if (request.method === "POST") {
    try {
      const data = await request.json();
      const { title, description, category, location, contact } = data;

      if (!title || !contact) {
        return new Response("Missing fields", { status: 400 });
      }

      await db.prepare(
        "INSERT INTO ads (title, description, category, location, contact) VALUES (?, ?, ?, ?, ?)"
      ).bind(title, description, category, location, contact).run();

      return Response.json({ success: true });
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  }

  return new Response("Method not allowed", { status: 405 });
}
