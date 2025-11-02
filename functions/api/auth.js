export async function onRequestPost({ request, env }) {
  const SECRET = env.JWT_SECRET; // ✅ Move this line inside the function
  const data = await request.json();
  const { email, phone, name, gender } = data;

  if (!email || !phone) {
    return new Response(JSON.stringify({ error: "Missing fields" }), {
      headers: { "Content-Type": "application/json" },
      status: 400,
    });
  }

  const userKey = `user:${email}`;
  const existing = await env.USERS_KV.get(userKey, { type: "json" });

  if (existing) {
    return new Response(JSON.stringify({ message: "User already exists" }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  await env.USERS_KV.put(userKey, JSON.stringify({ name, email, phone, gender }));

  return new Response(JSON.stringify({ message: "Account created successfully" }), {
    headers: { "Content-Type": "application/json" },
  });
}
