export async function onRequestPost({ request, env }) {
  try {
    const data = await request.json();
    const { username, password, mode } = data; // mode = "register" or "login"

    if (!username || !password || !mode)
      return new Response("Missing fields", { status: 400 });

    const userKey = `user:${username}`;
    const existing = await env.USERS_KV.get(userKey);

    if (mode === "register") {
      if (existing)
        return new Response(JSON.stringify({ error: "User already exists" }), { status: 400 });

      await env.USERS_KV.put(userKey, password);
      return new Response(JSON.stringify({ success: true, message: "Registered" }));
    }

    if (mode === "login") {
      if (!existing || existing !== password)
        return new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 });

      return new Response(JSON.stringify({ success: true, message: "Logged in" }));
    }

    return new Response("Invalid mode", { status: 400 });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}
