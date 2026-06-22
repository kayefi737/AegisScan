// AegisScan SPA. Vanilla JS, no build step. Talks to the same-origin API.
const API = "";
let token = localStorage.getItem("aegis_token") || null;
let authMode = "login";

const $ = (s) => document.querySelector(s);
const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };

const STATUS = {
  pass: ["PASS", "bg-emerald-100 text-emerald-800"],
  warn: ["WARN", "bg-amber-100 text-amber-800"],
  fail: ["FAIL", "bg-red-100 text-red-800"],
  info: ["INFO", "bg-slate-100 text-slate-600"],
};
const GRADE_COLOR = (g) => ({ "A+": "text-emerald-600", A: "text-emerald-600", B: "text-lime-600", C: "text-amber-600", D: "text-orange-600" }[g] || "text-red-600");

async function api(path, opts = {}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  if (token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch(API + path, Object.assign({}, opts, { headers }));
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  return res.status === 204 ? null : res.json();
}

// ---- View switching ----
function show(view) {
  $("#view-scan").classList.toggle("hidden", view !== "scan");
  $("#view-dashboard").classList.toggle("hidden", view !== "dashboard");
  document.querySelectorAll(".navlink").forEach((b) =>
    b.classList.toggle("text-slate-900", b.dataset.view === view));
  if (view === "dashboard") loadDashboard();
}
document.querySelectorAll(".navlink").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));

// ---- Scan flow ----
const STEPS = ["Resolving host…", "TLS handshake…", "Reading headers & cookies…", "DNS & email records…", "Scoring…"];
$("#scanForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const host = $("#hostInput").value.trim();
  if (!host) return;
  $("#error").classList.add("hidden");
  $("#report").classList.add("hidden");
  startProgress();
  try {
    const scan = await api("/api/scans", { method: "POST", body: JSON.stringify({ hostname: host }) });
    finishProgress();
    renderReport(scan);
  } catch (err) {
    stopProgress();
    $("#error").textContent = err.message;
    $("#error").classList.remove("hidden");
  }
});

let progressTimer;
function startProgress() {
  $("#progress").classList.remove("hidden");
  let i = 0, pct = 5;
  $("#progressBar").style.width = "5%";
  $("#progressLabel").textContent = STEPS[0];
  progressTimer = setInterval(() => {
    i = Math.min(i + 1, STEPS.length - 1); pct = Math.min(pct + 18, 90);
    $("#progressLabel").textContent = STEPS[i];
    $("#progressBar").style.width = pct + "%";
  }, 1100);
}
function finishProgress() { clearInterval(progressTimer); $("#progressBar").style.width = "100%"; setTimeout(() => $("#progress").classList.add("hidden"), 400); }
function stopProgress() { clearInterval(progressTimer); $("#progress").classList.add("hidden"); }

function renderReport(scan) {
  const r = scan.result;
  const box = $("#report"); box.innerHTML = "";
  const head = el("div", "flex items-end justify-between rounded-xl border border-slate-200 bg-white p-5");
  head.innerHTML = `
    <div>
      <div class="text-sm text-slate-500">${r.hostname}</div>
      <div class="text-5xl font-extrabold ${GRADE_COLOR(r.grade)}">${r.grade}</div>
      <div class="mt-1 text-sm text-slate-500">Score ${r.score}/100 &middot; ${r.duration_ms} ms &middot; engine ${r.engine_version}</div>
    </div>
    <div class="text-right text-sm">
      <div><b class="text-emerald-700">${r.summary.pass}</b> pass</div>
      <div><b class="text-amber-700">${r.summary.warn}</b> warn</div>
      <div><b class="text-red-700">${r.summary.fail}</b> fail</div>
      <div class="mt-2 flex gap-2 justify-end">
        <a class="text-xs underline" href="/api/scans/${scan.id}/report.html" target="_blank">HTML</a>
        ${token ? `<a class="text-xs underline" href="/api/scans/${scan.id}/report.pdf?">PDF</a>` : `<span class="text-xs text-slate-400" title="Sign in to download PDF">PDF 🔒</span>`}
      </div>
    </div>`;
  box.appendChild(head);

  r.categories.forEach((c) => {
    const card = el("div", "mt-4 rounded-xl border border-slate-200 bg-white p-5");
    card.appendChild(el("h3", "font-bold", `${c.label} <span class="text-sm font-normal text-slate-400">(${c.score}/${c.max_score})</span>`));
    c.findings.forEach((f) => {
      const [lbl, cls] = STATUS[f.status] || STATUS.info;
      const row = el("div", "mt-3 border-t border-slate-100 pt-3");
      row.innerHTML = `
        <div class="flex items-start gap-2">
          <span class="rounded px-1.5 py-0.5 text-[10px] font-bold ${cls}">${lbl}</span>
          <div class="flex-1">
            <div class="font-medium">${f.title}</div>
            <div class="text-sm text-slate-600">${f.detail}</div>
            ${f.fix ? `<div class="mt-1 text-sm">Fix: <code class="rounded bg-slate-100 px-1">${escapeHtml(f.fix)}</code></div>` : ""}
            ${f.owasp && f.owasp.length ? `<div class="mt-1 text-xs text-slate-400">${f.owasp.join(" · ")}</div>` : ""}
          </div>
        </div>`;
      card.appendChild(row);
    });
    box.appendChild(card);
  });
  box.classList.remove("hidden");
}

// ---- Dashboard ----
async function loadDashboard() {
  const d = $("#dash"); d.innerHTML = "Loading…";
  try {
    const s = await api("/api/dashboard");
    d.innerHTML = "";
    const stats = el("div", "grid grid-cols-2 gap-3 sm:grid-cols-4");
    [["Total scans", s.total_scans], ["Unique domains", s.unique_domains], ["Avg score", s.average_score], ["Grades", Object.keys(s.grade_distribution).length]]
      .forEach(([k, v]) => { const c = el("div", "rounded-xl border border-slate-200 bg-white p-4"); c.innerHTML = `<div class="text-2xl font-extrabold">${v}</div><div class="text-xs text-slate-500">${k}</div>`; stats.appendChild(c); });
    d.appendChild(stats);

    if (s.top_failures.length) {
      const tf = el("div", "mt-6 rounded-xl border border-slate-200 bg-white p-4");
      tf.innerHTML = "<div class='font-bold mb-2'>Most common failures</div>" +
        s.top_failures.map((f) => `<div class="flex justify-between border-t border-slate-100 py-1 text-sm"><span>${f.title}</span><span class="text-slate-400">${f.count}</span></div>`).join("");
      d.appendChild(tf);
    }

    const recent = el("div", "mt-6 rounded-xl border border-slate-200 bg-white p-4");
    recent.innerHTML = "<div class='font-bold mb-2'>Recent scans (masked)</div>" +
      (s.recent_scans.length ? s.recent_scans.map((r) => `<div class="flex justify-between border-t border-slate-100 py-1 text-sm"><span>${r.hostname}</span><span class="font-bold ${GRADE_COLOR(r.grade)}">${r.grade}</span></div>`).join("") : "<div class='text-sm text-slate-400'>No scans yet. Run one!</div>");
    d.appendChild(recent);
  } catch (err) { d.innerHTML = `<div class="text-red-600">${err.message}</div>`; }
}

// ---- Auth ----
function refreshAuthBtn() { $("#authBtn").textContent = token ? "Sign out" : "Sign in"; }
$("#authBtn").addEventListener("click", () => {
  if (token) { token = null; localStorage.removeItem("aegis_token"); refreshAuthBtn(); return; }
  $("#authModal").classList.remove("hidden"); $("#authModal").classList.add("flex");
});
$("#authClose").addEventListener("click", closeAuth);
function closeAuth() { $("#authModal").classList.add("hidden"); $("#authModal").classList.remove("flex"); $("#authError").classList.add("hidden"); }
$("#authToggle").addEventListener("click", () => {
  authMode = authMode === "login" ? "register" : "login";
  $("#authTitle").textContent = authMode === "login" ? "Sign in" : "Register";
  $("#authToggle").textContent = authMode === "login" ? "Need an account? Register" : "Have an account? Sign in";
});
$("#authForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = $("#authEmail").value, password = $("#authPass").value;
  try {
    if (authMode === "register") {
      await api("/api/auth/register", { method: "POST", body: JSON.stringify({ email, password }) });
    }
    const body = new URLSearchParams({ username: email, password });
    const res = await fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
    if (!res.ok) throw new Error((await res.json()).detail || "Login failed");
    token = (await res.json()).access_token;
    localStorage.setItem("aegis_token", token);
    refreshAuthBtn(); closeAuth();
  } catch (err) { $("#authError").textContent = err.message; $("#authError").classList.remove("hidden"); }
});

function escapeHtml(s) { return s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

refreshAuthBtn();
show("scan");
