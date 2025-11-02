export async function onRequestPost({ request, env }) {
  const data = await request.json();
  const { title, price, description, userEmail } = data;

  if (!title || !price || !userEmail) {
    return new Response(JSON.stringify({ error: "Missing required fields" }), {
      headers: { "Content-Type": "application/json" },
      status: 400,
    });
  }

  try {
    await env.IOT_DB.prepare(
      "INSERT INTO listings (title, price, description, user_email, created_at) VALUES (?, ?, ?, ?, ?)"
    ).bind(title, price, description, userEmail, new Date().toISOString()).run();

    return new Response(JSON.stringify({ success: true, message: "Listing added!" }), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: e.message }), {
      headers: { "Content-Type": "application/json" },
      status: 500,
    });
  }
}
