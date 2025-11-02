// ===========================
// 🌐 GLOBAL FUNCTIONS
// ===========================

// View ad details
function viewAd(id) {
  window.location.href = `productDetails.html?id=${id}`;
}

// ===========================
// 📢 LOAD ALL ADS (Homepage)
// ===========================
async function loadAds(containerId = "adsList", userId = null) {
  try {
    const res = await fetch("/api/ads");
    const ads = await res.json();

    const container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = "";

    const filtered = userId ? ads.filter(ad => ad.user_id == userId) : ads;

    if (filtered.length === 0) {
      container.innerHTML = "<p>No ads found.</p>";
      return;
    }

    filtered.forEach(ad => {
      const div = document.createElement("div");
      div.className = "ad-card";
      div.innerHTML = `
        <div class="ad-inner" onclick="viewAd(${ad.id})">
          <h3>${ad.title}</h3>
          <p>${ad.description ? ad.description.substring(0, 80) + "..." : "No description"}</p>
          <p><strong>Location:</strong> ${ad.location || "Unknown"}</p>
          <p><strong>Contact:</strong> ${ad.contact || "N/A"}</p>
        </div>
      `;
      container.appendChild(div);
    });
  } catch (err) {
    console.error("Error loading ads:", err);
  }
}

// ===========================
// 🧾 LOAD SINGLE PRODUCT DETAILS
// ===========================
async function loadProductDetails() {
  const params = new URLSearchParams(window.location.search);
  const id = params.get("id");
  if (!id) return;

  try {
    const res = await fetch(`/api/ads?id=${id}`);
    if (!res.ok) throw new Error("Ad not found");
    const ad = await res.json();

    document.getElementById("productName").innerText = ad.title;
    document.getElementById("description").innerText = ad.description;
    document.getElementById("description2").innerText = ad.description;
    document.getElementById("price").innerText = ad.category || "Uncategorized";
    document.getElementById("location").innerHTML = `<i class="fa-solid fa-location-dot"></i> ${ad.location || "Unknown"}`;
    document.getElementById("phoneL").innerText = ad.contact || "N/A";
    document.getElementById("nameL").innerText = ad.user_id ? "User #" + ad.user_id : "Unknown";
  } catch (err) {
    console.error("Error loading product details:", err);
  }
}

// ===========================
// 🗑️ DELETE AD
// ===========================
async function deleteAd(id) {
  if (!confirm("Are you sure you want to delete this ad?")) return;
  try {
    const res = await fetch("/api/ads", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const data = await res.json();
    alert(data.message || "Deleted");
    location.reload();
  } catch (err) {
    console.error("Error deleting ad:", err);
  }
}

// ===========================
// 👤 AUTH: SIGNUP
// ===========================
async function handleSignup(event) {
  event.preventDefault();
  const form = event.target;
  const name = form.querySelector("#signup_name")?.value.trim();
  const email = form.querySelector("#signup_email")?.value.trim();
  const password = form.querySelector("#signup_password")?.value.trim();
  const phone = form.querySelector("#signup_phone")?.value.trim() || "";
  const gender = form.querySelector("#signup_gender")?.value || "";

  try {
    const res = await fetch("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, email, password, phone, gender }),
    });

    const data = await res.json();

    if (res.ok) {
      alert(`✅ ${data.message}\n\n⚠️ Your Recovery Code:\n${data.recovery_code}\n\nSave it safely — it's shown only once!`);
      form.reset();
    } else {
      alert(data.error || "Signup failed");
    }
  } catch (err) {
    console.error("Signup error:", err);
    alert("Error signing up.");
  }
}

// ===========================
// 🔐 AUTH: LOGIN
// ===========================
async function handleLogin(event) {
  event.preventDefault();
  const form = event.target;
  const email = form.querySelector("#login_email")?.value.trim();
  const password = form.querySelector("#login_password")?.value.trim();

  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    const data = await res.json();

    if (res.ok) {
      alert("✅ Login successful!");
      localStorage.setItem("user", JSON.stringify(data.user));
      window.location.href = "dashboard.html";
    } else {
      alert(data.error || "Login failed");
    }
  } catch (err) {
    console.error("Login error:", err);
    alert("Error logging in.");
  }
}

// ===========================
// 🔄 AUTH: PASSWORD RESET
// ===========================
async function handlePasswordReset(event) {
  event.preventDefault();
  const form = event.target;
  const email = form.querySelector("#reset_email")?.value.trim();
  const recovery_code = form.querySelector("#reset_code")?.value.trim();
  const new_password = form.querySelector("#reset_password")?.value.trim();

  try {
    const res = await fetch("/api/auth/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, recovery_code, new_password }),
    });

    const data = await res.json();

    if (res.ok) {
      alert(`✅ ${data.message}\n\n⚠️ Your new recovery code:\n${data.new_recovery_code}\n\nSave it safely — it's shown only once!`);
      form.reset();
      window.location.href = "login.html";
    } else {
      alert(data.error || "Password reset failed");
    }
  } catch (err) {
    console.error("Password reset error:", err);
    alert("Error resetting password.");
  }
}

// ===========================
// ⚙️ PAGE INIT
// ===========================
document.addEventListener("DOMContentLoaded", () => {
  const path = window.location.pathname;

  if (path.endsWith("profile.html")) {
    const user = JSON.parse(localStorage.getItem("user"));
    if (user && user.id) loadAds("myAds", user.id);
  } else if (path.endsWith("productDetails.html")) {
    loadProductDetails();
  } else if (document.getElementById("adsList")) {
    loadAds("adsList");
  }

  // Auto-attach event listeners if forms exist
  const signupForm = document.getElementById("signupForm");
  if (signupForm) signupForm.addEventListener("submit", handleSignup);

  const loginForm = document.getElementById("loginForm");
  if (loginForm) loginForm.addEventListener("submit", handleLogin);

  const resetForm = document.getElementById("resetForm");
  if (resetForm) resetForm.addEventListener("submit", handlePasswordReset);
});
