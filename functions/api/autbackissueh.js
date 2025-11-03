export async function onRequestPost(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const action = url.searchParams.get("action");
  const DB = env.DB;
  const KV = env.USERS_KV;

  try {
    const data = await request.json();

    // ===== SIGNUP =====
    if (action === "signup") {
      const { name, email, password, phone, gender } = data;

      if (!name || !email || !password) {
        return new Response("Missing required fields", { status: 400 });
      }

      const existingUser = await DB.prepare(
        "SELECT * FROM users WHERE email = ?"
      )
        .bind(email)
        .first();

      if (existingUser) {
        return new Response(
          JSON.stringify({ error: "Email already registered" }),
          { status: 409 }
        );
      }

      await DB.prepare(
        "INSERT INTO users (name, email, password, phone, gender) VALUES (?, ?, ?, ?, ?)"
      )
        .bind(name, email, password, phone || "", gender || "")
        .run();

      await KV.put(`user_${email}`, JSON.stringify({ name, email }));

      return new Response(JSON.stringify({ success: true }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // ===== LOGIN =====
    if (action === "login") {
      const { email, password } = data;

      const user = await DB.prepare(
        "SELECT * FROM users WHERE email = ? AND password = ?"
      )
        .bind(email, password)
        .first();

      if (!user) {
        return new Response(
          JSON.stringify({ error: "Invalid credentials" }),
          { status: 401 }
        );
      }

      await KV.put(`session_${email}`, "true", { expirationTtl: 3600 });

      return new Response(
        JSON.stringify({
          success: true,
          name: user.name,
          email: user.email,
        }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // ===== FORGOT PASSWORD =====
    if (action === "forgot") {
      const { email } = data;

      const user = await DB.prepare(
        "SELECT * FROM users WHERE email = ?"
      )
        .bind(email)
        .first();

      if (!user) {
        return new Response(
          JSON.stringify({ error: "User not found" }),
          { status: 404 }
        );
      }

      const recoveryCode = Math.floor(100000 + Math.random() * 900000).toString();

      await DB.prepare(
        "UPDATE users SET recovery_code = ? WHERE email = ?"
      )
        .bind(recoveryCode, email)
        .run();

      return new Response(
        JSON.stringify({
          success: true,
          recoveryCode,
        }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // ===== RESET PASSWORD =====
    if (action === "reset") {
      const { email, code, newPassword } = data;

      const user = await DB.prepare(
        "SELECT * FROM users WHERE email = ? AND recovery_code = ?"
      )
        .bind(email, code)
        .first();

      if (!user) {
        return new Response(
          JSON.stringify({ error: "Invalid recovery code" }),
          { status: 400 }
        );
      }

      await DB.prepare(
        "UPDATE users SET password = ?, recovery_code = NULL WHERE email = ?"
      )
        .bind(newPassword, email)
        .run();

      return new Response(JSON.stringify({ success: true }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // ===== UNKNOWN ACTION =====
    return new Response("Invalid action", { status: 400 });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
    });
  }
}
