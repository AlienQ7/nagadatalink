export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const email = url.searchParams.get("email");

  let query = "SELECT * FROM listings";
  let bindings = [];

  if (email) {
    query += " WHERE user_email = ?";
    bindings.push(email);
  }

  const { results } = await env.DB.prepare(query).bind(...bindings).all();

  return new Response(JSON.stringify(results), {
    headers: { "Content-Type": "application/json" },
  });
}
