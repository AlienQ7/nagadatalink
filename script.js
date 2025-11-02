// ============ GLOBAL FUNCTIONS ============
function viewAd(id) {
  window.location.href = `productDetails.html?id=${id}`;
}

// ============ LOAD ALL ADS ============
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

// ============ PRODUCT DETAILS ============
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

// ============ SIGNUP HANDLER ============
async function handleSignup(e) {
  e.preventDefault();
  const name = document.getElementById("signupName").value;
  const email = document.getElementById("signupEmail").value;
  const password = document.getElementById("signupPassword").value;

  const res = await fetch("/api/auth/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, email, password }),
  });

  const data = await res.json();
  if (res.ok && data.recovery_code) {
    showRecoveryPopup(data.recovery_code);
  } else {
    alert(data.error || "Signup failed");
  }
}

// ============ LOGIN HANDLER ============
async function handleLogin(e) {
  e.preventDefault();
  const email = document.getElementById("loginEmail").value;
  const password = document.getElementById("loginPassword").value;

  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  const data = await res.json();
  if (res.ok && data.user) {
    localStorage.setItem("user", JSON.stringify(data.user));
    window.location.href = "dashboard.html";
  } else {
    alert(data.error || "Login failed");
  }
}

// ============ RECOVERY POPUP ============
function showRecoveryPopup(code) {
  const overlay = document.createElement("div");
  overlay.style = `
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(0,0,0,0.7); display: flex;
    align-items: center; justify-content: center; z-index: 1000;
  `;
  overlay.innerHTML = `
    <div style="background:#fff; padding:20px; border-radius:10px; text-align:center; max-width:350px;">
      <h2 style="color:#ff9800;">⚠️ Important!</h2>
      <p style="margin:10px 0;">Your recovery code (save it safely):</p>
      <div style="font-weight:bold; font-size:18px; margin:10px 0; color:#333;">${code}</div>
      <p style="color:red; font-size:14px;">You will not see this code again.</p>
      <button id="copyBtn">Copy Code</button>
      <button id="okBtn" style="margin-left:10px;">I Saved It</button>
    </div>
  `;
  document.body.appendChild(overlay);

  document.getElementById("copyBtn").onclick = () => {
    navigator.clipboard.writeText(code);
    alert("Recovery code copied!");
  };
  document.getElementById("okBtn").onclick = () => overlay.remove();
}

// ============ INIT ============
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

  const signupForm = document.getElementById("signupForm");
  const loginForm = document.getElementById("loginForm");
  if (signupForm) signupForm.addEventListener("submit", handleSignup);
  if (loginForm) loginForm.addEventListener("submit", handleLogin);
});
