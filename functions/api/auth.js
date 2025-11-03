// functions/api/auth.js
export async function onRequestPost(context) {
  const { request, env } = context;
  const DB = env.DB; // D1 binding in wrangler.toml

  // Helper: SHA-256 hex hash (worker/subtle)
  async function hashPassword(password) {
    const enc = new TextEncoder();
    const data = enc.encode(password);
    const digest = await crypto.subtle.digest("SHA-256", data);
    const bytes = Array.from(new Uint8Array(digest));
    return bytes.map(b => b.toString(16).padStart(2, "0")).join("");
  }

  // Helper: strong recovery code (12 chars alnum)
  function makeRecoveryCode(len = 12) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let out = "";
    const rand = crypto.getRandomValues;
    while (out.length < len) {
      // generate a random 32-bit value, extract bytes
      const r = new Uint32Array(1);
      rand(r);
      let v = r[0];
      while (v && out.length < len) {
        out += chars[v % chars.length];
        v = Math.floor(v / chars.length);
      }
    }
    return out;
  }

  // Parse JSON safely
  let body = {};
  try {
    body = await request.json();
  } catch (e) {
    // no JSON body
    return new Response(JSON.stringify({ error: "Invalid or missing JSON body" }), {
      status: 400,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    });
  }

  // Determine action: prefer explicit body.action, fallback to URL path
  const url = new URL(request.url);
  const pathname = url.pathname || "";
  let action = (body.action || "").toString().toLowerCase();
  if (!action) {
    if (pathname.endsWith("/signup")) action = "signup";
    else if (pathname.endsWith("/login")) action = "login";
    else if (pathname.endsWith("/forgot") || pathname.endsWith("/reset")) action = "forgot";
  }

  if (!action) {
    return new Response(JSON.stringify({ error: "Missing action. Use { action: 'signup' } or { action: 'login' } in request body." }), {
      status: 400,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    });
  }

  // -------- SIGNUP --------
  if (action === "signup") {
    const name = (body.name || "").trim();
    const email = (body.email || "").trim().toLowerCase();
    const password = body.password || "";
    const phone = body.phone || null;
    const gender = body.gender || null;

    if (!name || !email || !password) {
      return new Response(JSON.stringify({ error: "Missing required fields: name, email, password" }), {
        status: 400,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    }

    try {
      // check existing
      const existing = await DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
      if (existing) {
        return new Response(JSON.stringify({ error: "User already exists" }), {
          status: 409,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
        });
      }

      const hashed = await hashPassword(password);
      const recovery_code = makeRecoveryCode(12);

      await DB.prepare(
        "INSERT INTO users (name, email, password, phone, gender, recovery_code) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(name, email, hashed, phone, gender, recovery_code).run();

      // return recovery code once (client must show/save it)
      return new Response(JSON.stringify({
        message: "Signup successful",
        recovery_code // show once — will be stored server-side
      }), {
        status: 201,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    } catch (err) {
      console.error("signup error", err);
      return new Response(JSON.stringify({ error: "Internal server error (signup)" }), {
        status: 500,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    }
  }

  // -------- LOGIN --------
  if (action === "login") {
    const email = (body.email || "").trim().toLowerCase();
    const password = body.password || "";

    if (!email || !password) {
      return new Response(JSON.stringify({ error: "Missing email or password" }), {
        status: 400,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    }

    try {
      const user = await DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
      if (!user) {
        return new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
        });
      }

      const hashed = await hashPassword(password);

      // Accept either hashed match OR plaintext match (backwards compatibility)
      const stored = user.password || "";
      const isHashedMatch = (hashed === stored);
      const isPlainMatch = (password === stored);

      if (!isHashedMatch && !isPlainMatch) {
        return new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
        });
      }

      // If plaintext match, upgrade to hashed password
      if (isPlainMatch && !isHashedMatch) {
        try {
          await DB.prepare("UPDATE users SET password = ? WHERE id = ?").bind(hashed, user.id).run();
        } catch (e) {
          console.error("password upgrade failed", e);
          // not fatal — continue
        }
      }

      // Remove sensitive fields before returning
      const safeUser = {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone || null,
        gender: user.gender || null
      };

      return new Response(JSON.stringify({ message: "Login successful", user: safeUser }), {
        status: 200,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    } catch (err) {
      console.error("login error", err);
      return new Response(JSON.stringify({ error: "Internal server error (login)" }), {
        status: 500,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    }
  }

  // -------- FORGOT / RESET (basic flow) --------
  if (action === "forgot") {
    // Expect: { email, recovery_code, new_password } OR { email } to request reset link (here we rely on recovery codes)
    const email = (body.email || "").trim().toLowerCase();

    if (!email) {
      return new Response(JSON.stringify({ error: "Missing email" }), {
        status: 400,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    }

    try {
      const user = await DB.prepare("SELECT id, recovery_code FROM users WHERE email = ?").bind(email).first();
      if (!user) {
        // don't reveal whether user exists
        return new Response(JSON.stringify({ message: "If an account exists, instructions were sent." }), {
          status: 200,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
        });
      }

      // If client provided both recovery_code and new_password -> perform reset
      if (body.recovery_code && body.new_password) {
        const provided = String(body.recovery_code);
        if (!user.recovery_code || provided !== user.recovery_code) {
          return new Response(JSON.stringify({ error: "Invalid recovery code" }), {
            status: 401,
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
          });
        }

        const newHashed = await hashPassword(String(body.new_password));
        const newCode = makeRecoveryCode(12); // rotate code
        await DB.prepare("UPDATE users SET password = ?, recovery_code = ? WHERE id = ?").bind(newHashed, newCode, user.id).run();

        return new Response(JSON.stringify({ message: "Password reset successful", recovery_code: newCode }), {
          status: 200,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
        });
      }

      // Otherwise: client asked to start reset flow — we'll return success message (no email sent by this function)
      // (You can implement email sending separately; for now return a generic success response.)
      return new Response(JSON.stringify({ message: "If an account exists, follow the reset instructions you received." }), {
        status: 200,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    } catch (err) {
      console.error("forgot error", err);
      return new Response(JSON.stringify({ error: "Internal server error (forgot)" }), {
        status: 500,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    }
  }

  // Unknown action
  return new Response(JSON.stringify({ error: "Unknown action" }), {
    status: 400,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  });
}
