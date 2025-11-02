export async function onRequest(context) {
  const { request, env } = context;
  const db = env.DB;
  const url = new URL(request.url);
  const id = url.searchParams.get("id");

  // ---------- GET ----------
  if (request.method === "GET") {
    try {
      // Fetch single ad by ?id=
      if (id) {
        const ad = await db.prepare("SELECT * FROM ads WHERE id = ?").bind(id).first();
        if (!ad) return new Response("Ad not found", { status: 404 });
        return Response.json(ad);
      }

      // Fetch all ads
      const { results } = await db.prepare("SELECT * FROM ads ORDER BY id DESC").all();
      return Response.json(results);
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  }

  // ---------- POST ----------
  if (request.method === "POST") {
    try {
      const data = await request.json();
      const { title, description, category, location, contact, user_id } = data;

      if (!title || !contact) {
        return new Response("Missing fields", { status: 400 });
      }

      await db
        .prepare(
          "INSERT INTO ads (title, description, category, location, contact, user_id) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(title, description, category, location, contact, user_id)
        .run();

      return Response.json({ success: true, message: "Ad added successfully!" });
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  }

  // ---------- DELETE ----------
  if (request.method === "DELETE") {
    try {
      const data = await request.json();
      const { id } = data;
      if (!id) return new Response("Missing ad ID", { status: 400 });

      await db.prepare("DELETE FROM ads WHERE id = ?").bind(id).run();
      return Response.json({ success: true, message: "Ad deleted successfully!" });
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  }

  return new Response("Method not allowed", { status: 405 });
}
