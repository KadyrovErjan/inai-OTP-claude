/* Admin login + security dashboard. The admin key is typed by the operator and
 * exchanged for an HttpOnly session cookie; it never lives in JS or the page. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const root = document.documentElement;
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  setTimeout(() => { void document.body.offsetWidth; root.classList.add("is-ready"); }, 30);

  const header = $("header");
  if (header) {
    const onScroll = () => header.classList.toggle("is-scrolled", window.scrollY > 8);
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
  }

  // ------------------------------------------------------------- login page
  const form = $("login-form");
  if (form) {
    const input = $("admin-key");
    input.focus();
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const btn = $("login-btn");
      const slot = $("login-banner");
      slot.replaceChildren();
      input.classList.remove("is-error");
      if (!input.value) { input.classList.add("is-error"); return; }
      btn.classList.add("is-loading"); btn.disabled = true;
      let res = null;
      try {
        res = await fetch("/admin/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ key: input.value }),
        });
      } catch { /* network */ }
      btn.classList.remove("is-loading"); btn.disabled = false;
      input.value = "";
      if (res && res.ok) { location.reload(); return; }
      input.classList.add("is-error");
      const b = document.createElement("div");
      b.className = "banner banner-error";
      const s = document.createElement("span");
      s.textContent = !res ? "Нет соединения с сервером."
        : res.status === 429 ? "Слишком много попыток входа. Подождите минуту."
        : "Неверный ключ администратора.";
      b.append(s);
      slot.append(b);
      input.focus();
    });
    return;
  }

  // ------------------------------------------------------------- dashboard
  if (!$("dashboard")) return;
  let timer = null;
  let first = true;
  const prev = {};
  const seen = new Set();

  const cell = (value, cls) => {
    const td = document.createElement("td");
    if (cls) td.className = cls;
    td.textContent = value == null ? "—" : String(value);
    return td;
  };
  const describe = (d) => Object.entries(d || {}).map(([k, v]) => `${k}: ${v}`).join(" · ") || "—";
  const keyOf = (e) => `${e.ts_ms}|${e.event}|${e.phone}|${e.ip}`;

  function setKpi(id, value) {
    const el = $(id);
    if (first && !reduceMotion && value > 0) {
      const t0 = performance.now();
      const dur = 600;
      const tick = (now) => {
        const p = Math.min(1, (now - t0) / dur);
        const eased = 1 - Math.pow(1 - p, 3);
        el.textContent = Math.round(value * eased).toLocaleString("ru-RU");
        if (p < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    } else {
      el.textContent = value.toLocaleString("ru-RU");
      if (prev[id] !== undefined && prev[id] !== value) {
        el.classList.add("flash");
        requestAnimationFrame(() => requestAnimationFrame(() => el.classList.remove("flash")));
      }
    }
    prev[id] = value;
  }

  async function get(url) {
    const res = await fetch(url, { credentials: "same-origin" });
    if (res.status === 401) { location.reload(); throw new Error("unauthorized"); }
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
  }

  async function load() {
    const filter = $("event-filter").value;
    const btn = $("refresh");
    btn.classList.add("is-loading");
    try {
      const [stats, ev] = await Promise.all([
        get("/admin/api/stats"),
        get("/admin/api/events?limit=200" + (filter ? "&event=" + encodeURIComponent(filter) : "")),
      ]);
      setKpi("k-issued", stats.otp_issued);
      setKpi("k-verified", stats.verified);
      setKpi("k-failed", stats.failed);
      setKpi("k-blocks", stats.blocks);
      setKpi("k-limited", stats.rate_limited);

      const body = $("events");
      const rows = ev.events.map((e) => {
        const tr = document.createElement("tr");
        const k = keyOf(e);
        if (!first && !seen.has(k)) tr.className = "is-new";
        seen.add(k);
        tr.append(cell(e.ts.replace("T", " ").replace("Z", ""), "mono"));
        const td = document.createElement("td");
        const badge = document.createElement("span");
        badge.className = "ev " + e.severity;
        badge.textContent = e.event;
        td.append(badge);
        tr.append(td);
        tr.append(cell(e.phone, "mono"));
        tr.append(cell(e.ip, "mono"));
        tr.append(cell(describe(e.details), "details"));
        return tr;
      });
      body.replaceChildren(...rows);
      $("empty").hidden = rows.length > 0;
      $("updated").textContent = "обновлено в " + new Date().toLocaleTimeString("ru-RU");
      first = false;
    } catch (err) {
      $("updated").textContent = "ошибка загрузки: " + err.message;
    } finally {
      setTimeout(() => btn.classList.remove("is-loading"), 300);
    }
  }

  function schedule() {
    if (timer) clearInterval(timer);
    timer = $("auto-refresh").checked ? setInterval(() => { if (!document.hidden) load(); }, 5000) : null;
  }

  $("refresh").addEventListener("click", load);
  $("event-filter").addEventListener("change", () => { seen.clear(); first = true; load(); });
  $("auto-refresh").addEventListener("change", schedule);
  $("logout").addEventListener("click", async (e) => {
    e.preventDefault();
    await fetch("/admin/logout", { method: "POST", credentials: "same-origin" });
    location.reload();
  });
  load();
  schedule();
})();
