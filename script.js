// -------------------------------
// Signup / Login / Forgot Functions
// -------------------------------
document.addEventListener("DOMContentLoaded", () => {
  const signupForm = document.getElementById("signupForm");
  const loginForm = document.getElementById("loginForm");
  const forgotForm = document.getElementById("forgotForm");

  // -------------------------------
  // SIGNUP
  // -------------------------------
  if (signupForm) {
    signupForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const name = document.getElementById("signupName").value.trim();
      const email = document.getElementById("signupEmail").value.trim();
      const password = document.getElementById("signupPassword").value.trim();
      const gender = document.getElementById("signupGender")?.value || null;

      if (!name || !email || !password) {
        alert("All required fields must be filled.");
        return;
      }

      try {
        const response = await fetch("/api/auth", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "signup", name, email, password, gender }),
        });

        const result = await response.json();

        if (!response.ok) {
          alert(result.error || "Signup failed.");
          return;
        }

        // Show recovery code once
        if (result.recovery_code) {
          alert(
            "Signup successful!\n\nIMPORTANT: Your Recovery Code is:\n\n" +
              result.recovery_code +
              "\n\nKeep it safe — it will only be shown once."
          );
        } else {
          alert("Signup successful!");
        }

        window.location.href = "index.html";
      } catch (err) {
        console.error(err);
        alert("Network error during signup.");
      }
    });
  }

  // -------------------------------
  // LOGIN
  // -------------------------------
  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const email = document.getElementById("loginEmail").value.trim();
      const password = document.getElementById("loginPassword").value.trim();

      if (!email || !password) {
        alert("Please fill all fields.");
        return;
      }

      try {
        const response = await fetch("/api/auth", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "login", email, password }),
        });

        const result = await response.json();

        if (!response.ok) {
          alert(result.error || "Login failed.");
          return;
        }

        localStorage.setItem("user", JSON.stringify(result.user));
        alert("Login successful!");
        window.location.href = "dashboard.html";
      } catch (err) {
        console.error(err);
        alert("Network error during login.");
      }
    });
  }

  // -------------------------------
  // FORGOT PASSWORD / RECOVER
  // -------------------------------
  if (forgotForm) {
    forgotForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const email = document.getElementById("forgotEmail").value.trim();
      const recoveryCode = document.getElementById("forgotRecoveryCode").value.trim();
      const newPassword = document.getElementById("forgotNewPassword").value.trim();

      if (!email || !recoveryCode || !newPassword) {
        alert("All fields are required.");
        return;
      }

      try {
        const response = await fetch("/api/auth", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            action: "forgot",
            email,
            recovery_code: recoveryCode,
            new_password: newPassword,
          }),
        });

        const result = await response.json();

        if (!response.ok) {
          alert(result.error || "Password reset failed.");
          return;
        }

        if (result.new_recovery_code) {
          alert(
            "Password reset successful!\n\nYour NEW recovery code is:\n\n" +
              result.new_recovery_code +
              "\n\nKeep it safe!"
          );
        } else {
          alert("Password reset successful!");
        }

        window.location.href = "index.html";
      } catch (err) {
        console.error(err);
        alert("Network error during password reset.");
      }
    });
  }
});
