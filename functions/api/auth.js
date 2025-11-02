export async function onRequestPost({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname;
  const DB = env.DB;

  // ===== Helper: hash password =====
  async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  }

  // ===== Helper: generate secure random recovery code =====
  function generateRecoveryCode() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let code = "";
    for (let i = 0; i < 16; i++) code += chars.charAt(Math.floor(Math.random() * chars.length));
    return code;
  }

  // ===== Parse body =====
  const data = await request.json();
  const { name, email, password, phone, gender, recovery_code, newPassword } = data;

  // ===== SIGNUP =====
  if (path.endsWith("/signup")) {
    if (!email || !password || !name) {
      return new Response(JSON.stringify({ error: "Missing required fields" }), {
        headers: { "Content-Type": "application/json" },
        status: 400,
      });
    }

    const existing = await DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
    if (existing) {
      return new Response(JSON.stringify({ error: "User already exists" }), {
        headers: { "Content-Type": "application/json" },
        status: 409,
      });
    }

    const hashed = await hashPassword(password);
    const recoveryCode = generateRecoveryCode();

    await DB.prepare(
      "INSERT INTO users (name, email, password, phone, gender, recovery_code) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(name, email, hashed, phone || null, gender || null, recoveryCode).run();

    return new Response(
      JSON.stringify({
        message: "Signup successful. Save this recovery code securely!",
        recovery_code: recoveryCode,
      }),
      { headers: { "Content-Type": "application/json" } }
    );
  }

  // ===== LOGIN =====
  if (path.endsWith("/login")) {
    if (!email || !password) {
      return new Response(JSON.stringify({ error: "Missing email or password" }), {
        headers: { "Content-Type": "application/json" },
        status: 400,
      });
    }

    const user = await DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
    if (!user) {
      return new Response(JSON.stringify({ error: "User not found" }), {
        headers: { "Content-Type": "application/json" },
        status: 404,
      });
    }

    const hashed = await hashPassword(password);
    if (hashed !== user.password) {
      return new Response(JSON.stringify({ error: "Incorrect password" }), {
        headers: { "Content-Type": "application/json" },
        status: 401,
      });
    }

    delete user.password;
    return new Response(JSON.stringify({ message: "Login successful", user }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  // ===== RESET PASSWORD (forgot password) =====
  if (path.endsWith("/reset")) {
    if (!email || !recovery_code || !newPassword) {
      return new Response(JSON.stringify({ error: "Missing fields" }), {
        headers: { "Content-Type": "application/json" },
        status: 400,
      });
    }

    const user = await DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
    if (!user) {
      return new Response(JSON.stringify({ error: "User not found" }), {
        headers: { "Content-Type": "application/json" },
        status: 404,
      });
    }

    if (user.recovery_code !== recovery_code) {
      return new Response(JSON.stringify({ error: "Invalid recovery code" }), {
        headers: { "Content-Type": "application/json" },
        status: 401,
      });
    }

    const newHashed = await hashPassword(newPassword);
    const newRecovery = generateRecoveryCode();

    await DB.prepare(
      "UPDATE users SET password = ?, recovery_code = ? WHERE email = ?"
    ).bind(newHashed, newRecovery, email).run();

    return new Response(
      JSON.stringify({
        message: "Password reset successful. Save your new recovery code!",
        new_recovery_code: newRecovery,
      }),
      { headers: { "Content-Type": "application/json" } }
    );
  }

  // ===== Invalid Endpoint =====
  return new Response(JSON.stringify({ error: "Invalid endpoint" }), {
    headers: { "Content-Type": "application/json" },
    status: 404,
  });
}
