/* OTP Secure — landing + OTP flow.
 * Every decision comes from the backend: the page shows "verified" only after
 * HTTP 200 from /otp/verify. Timers are visual mirrors of server-side TTLs. */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const root = document.documentElement;
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const RING = 2 * Math.PI * 11;

  // ------------------------------------------------------------ entrance
  // never depend on rAF alone: content must appear even in background tabs
  let started = false;
  const start = () => {
    if (started) return;
    started = true;
    void document.body.offsetWidth; // commit initial (hidden) styles first
    root.classList.add("is-ready");
  };
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => setTimeout(start, 0));
  setTimeout(start, 350);

  // header hairline on scroll
  const header = $("header");
  const onScroll = () => header.classList.toggle("is-scrolled", window.scrollY > 8);
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  // reveal groups once
  const io = "IntersectionObserver" in window
    ? new IntersectionObserver((entries) => {
        entries.forEach((e) => {
          if (!e.isIntersecting) return;
          e.target.classList.add("is-visible");
          io.unobserve(e.target);
          if (e.target.id === "attack") runAttack();
        });
      }, { rootMargin: "0px 0px -12% 0px" })
    : null;
  document.querySelectorAll(".in-view-group").forEach((el) => (io ? io.observe(el) : el.classList.add("is-visible")));

  // ------------------------------------------------------------ screens
  const order = ["phone", "code", "success", "blocked"];
  const tags = { phone: "POST /otp/send", code: "POST /otp/verify", success: "200 OK", blocked: "423 Locked" };
  let current = "phone";

  function show(name) {
    if (name === current) return;
    const forward = order.indexOf(name) > order.indexOf(current);
    const prev = $("screen-" + current);
    const next = $("screen-" + name);
    prev.classList.remove("is-active");
    prev.classList.toggle("is-before", forward);
    prev.setAttribute("aria-hidden", "true");
    prev.inert = true;
    next.classList.remove("is-before");
    // start the incoming screen on the correct side, then activate
    next.style.transition = "none";
    next.style.transform = forward ? "translateX(14px)" : "translateX(-14px)";
    void next.offsetWidth;
    next.style.transition = "";
    next.style.transform = "";
    next.classList.add("is-active");
    next.setAttribute("aria-hidden", "false");
    next.inert = false;
    current = name;

    const step = { phone: 1, code: 2, success: 3, blocked: 3 }[name];
    [1, 2, 3].forEach((i) => $("step-" + i).classList.toggle("on", i <= step));
    $("card-tag").textContent = tags[name];
    $("card").classList.toggle("is-success", name === "success");
    $("card").classList.toggle("is-blocked", name === "blocked");
    if (name === "code") setTimeout(() => cells[firstEmpty()].focus({ preventScroll: true }), 260);
  }
  order.filter((n) => n !== "phone").forEach((n) => ($("screen-" + n).inert = true));

  // ------------------------------------------------------------ helpers
  const fmt = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;

  function banner(slot, text, kind) {
    const el = $(slot);
    el.replaceChildren();
    if (!text) return;
    const b = document.createElement("div");
    b.className = "banner banner-" + kind;
    const span = document.createElement("span");
    span.textContent = text;
    b.append(span);
    el.append(b);
    return span;
  }

  function busy(btn, on) {
    btn.classList.toggle("is-loading", on);
    btn.disabled = on;
    btn.setAttribute("aria-busy", on ? "true" : "false");
  }

  async function api(path, body) {
    try {
      const res = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      let data = {};
      try { data = await res.json(); } catch { /* empty body */ }
      return { status: res.status, data };
    } catch {
      return { status: 0, data: {} };
    }
  }

  function validation(data) {
    const d = (data.details || [])[0];
    if (d && d.field === "msisdn") return "Введите номер в международном формате, например +996 700 123 456";
    if (d && d.field === "code") return "Код состоит из 6 цифр";
    return "Проверьте введённые данные";
  }

  const timers = {};
  function stop(name) { if (timers[name]) { clearInterval(timers[name]); timers[name] = null; } }
  function stopAll() { Object.keys(timers).forEach(stop); }

  function countdown(name, seconds, onTick, onDone) {
    stop(name);
    const end = Date.now() + seconds * 1000;
    const tick = () => {
      const left = Math.max(0, Math.ceil((end - Date.now()) / 1000));
      onTick(left);
      if (left === 0) { stop(name); onDone && onDone(); }
    };
    tick();
    timers[name] = setInterval(tick, 250);
  }

  // ------------------------------------------------------------ OTP timer ring
  const ring = $("ring");
  ring.style.strokeDasharray = RING.toFixed(2);

  function startTtl(total) {
    const timer = $("timer");
    timer.classList.remove("is-low", "is-over");
    ring.style.transition = "none";
    ring.style.strokeDashoffset = "0";
    void ring.getBoundingClientRect();
    ring.style.transition = "";
    let last = -1;
    countdown("ttl", total, (left) => {
      if (left === last) return;
      last = left;
      $("ttl-label").textContent = fmt(left);
      ring.style.strokeDashoffset = (RING * (1 - left / total)).toFixed(2);
      timer.classList.toggle("is-low", left > 0 && left <= 20);
      timer.classList.toggle("is-over", left === 0);
    }, () => banner("code-banner", "Срок действия кода истёк. Запросите новый.", "warning"));
  }

  function startCooldown(seconds) {
    const btn = $("resend-btn");
    countdown("cooldown", seconds, (left) => {
      btn.disabled = left > 0;
      btn.textContent = left > 0 ? `Снова через ${fmt(left)}` : "Отправить снова";
    });
  }

  function showBlocked(seconds, reason) {
    stopAll();
    $("blocked-reason").textContent = reason || "5 неверных кодов подряд.";
    countdown("block", seconds || 900, (left) => {
      $("blocked-timer").textContent = fmt(left);
      if (left === 0) $("blocked-reason").textContent = "Блокировка снята. Можно запросить новый код.";
    });
    show("blocked");
  }

  // ------------------------------------------------------------ send
  const state = { msisdn: "" };

  async function sendCode(fromCode) {
    const slot = fromCode ? "code-banner" : "phone-banner";
    const btn = fromCode ? $("resend-btn") : $("send-btn");
    const input = $("msisdn");
    const msisdn = fromCode ? state.msisdn : input.value.trim();
    banner(slot, "");
    input.classList.remove("is-error");
    if (!msisdn) {
      input.classList.add("is-error");
      banner(slot, "Введите номер телефона", "error");
      input.focus();
      return;
    }
    if (fromCode) btn.disabled = true; else busy(btn, true);
    const { status, data } = await api("/otp/send", { msisdn });
    if (!fromCode) busy(btn, false);

    if (status === 200) {
      state.msisdn = msisdn;
      $("phone-label").textContent = msisdn;
      clearCells();
      startTtl(data.expires_in || 120);
      startCooldown(data.retry_after || 30);
      show("code");
      if (fromCode) {
        banner("code-banner", "Новый код отправлен. Предыдущий больше не действует.", "success");
        cells[0].focus({ preventScroll: true });
      }
      return;
    }
    if (status === 423) return showBlocked(data.retry_after, "Номер заблокирован после 5 неверных кодов.");
    if (status === 429) {
      const wait = data.retry_after || 30;
      const prefix = data.reason === "window_limit" ? "Лимит: не больше 3 кодов за 10 минут." : "Слишком частые запросы.";
      const target = banner(slot, `${prefix} Повторите через ${fmt(wait)}.`, "warning");
      countdown("retry-" + slot, wait, (left) => {
        if (target.isConnected) target.textContent = left > 0 ? `${prefix} Повторите через ${fmt(left)}.` : `${prefix} Можно повторить.`;
      });
      if (fromCode) startCooldown(wait);
      return;
    }
    if (fromCode) btn.disabled = false;
    if (status === 422) { input.classList.add("is-error"); return banner(slot, validation(data), "error"); }
    banner(slot, status === 0 ? "Нет соединения с сервером." : "Сервис временно недоступен. Попробуйте позже.", "error");
  }

  // ------------------------------------------------------------ cells
  const cells = Array.from(document.querySelectorAll(".cell"));
  const otpBox = $("otp");
  const code = () => cells.map((c) => c.value).join("");
  const firstEmpty = () => { const i = cells.findIndex((c) => !c.value); return i === -1 ? 5 : i; };

  function refresh() {
    cells.forEach((c) => {
      const filled = !!c.value;
      if (filled && !c.classList.contains("is-filled")) c.classList.add("is-filled");
      if (!filled) c.classList.remove("is-filled");
      c.classList.remove("is-error");
    });
    $("verify-btn").disabled = !/^\d{6}$/.test(code());
  }

  function clearCells() {
    cells.forEach((c) => { c.value = ""; c.classList.remove("is-filled", "is-error", "is-success"); });
    $("verify-btn").disabled = true;
  }

  function fill(from, text) {
    const digits = text.replace(/\D/g, "").slice(0, 6 - from).split("");
    digits.forEach((d, i) => { cells[from + i].value = d; });
    refresh();
    if (/^\d{6}$/.test(code())) {
      cells[5].blur();
      verify();
    } else {
      cells[Math.min(from + digits.length, 5)].focus();
    }
  }

  cells.forEach((cell, i) => {
    cell.addEventListener("input", () => {
      const v = cell.value.replace(/\D/g, "");
      if (v.length > 1) { cell.value = ""; return fill(i, v); }
      cell.value = v;
      refresh();
      if (v && i < 5) cells[i + 1].focus();
      if (v && /^\d{6}$/.test(code())) verify();
    });
    cell.addEventListener("keydown", (e) => {
      if (e.key === "Backspace" && !cell.value && i > 0) {
        e.preventDefault();
        cells[i - 1].value = "";
        cells[i - 1].focus();
        refresh();
      } else if (e.key === "ArrowLeft" && i > 0) { e.preventDefault(); cells[i - 1].focus(); }
      else if (e.key === "ArrowRight" && i < 5) { e.preventDefault(); cells[i + 1].focus(); }
      else if (e.key === "Enter") { e.preventDefault(); verify(); }
    });
    cell.addEventListener("paste", (e) => {
      e.preventDefault();
      fill(i, (e.clipboardData || window.clipboardData).getData("text"));
    });
    cell.addEventListener("focus", () => cell.select());
  });

  function shake() {
    cells.forEach((c) => c.classList.add("is-error"));
    otpBox.classList.remove("shake");
    void otpBox.offsetWidth;
    otpBox.classList.add("shake");
  }
  otpBox.addEventListener("animationend", () => otpBox.classList.remove("shake"));

  // ------------------------------------------------------------ verify
  let verifying = false;

  async function verify() {
    const value = code();
    if (verifying || !/^\d{6}$/.test(value)) return;
    verifying = true;
    banner("code-banner", "");
    const btn = $("verify-btn");
    busy(btn, true);
    const { status, data } = await api("/otp/verify", { msisdn: state.msisdn, code: value });
    busy(btn, false);
    verifying = false;

    if (status === 200 && data.verified === true) {
      cells.forEach((c) => c.classList.add("is-success"));
      stopAll();
      $("success-phone").textContent = state.msisdn;
      setTimeout(() => show("success"), reduceMotion ? 0 : 220);
      return;
    }
    if (status === 401) {
      shake();
      const left = data.attempts_left;
      banner("code-banner", left !== undefined ? `Неверный код. Осталось попыток: ${left}.` : "Неверный код.", "error");
      setTimeout(() => { clearCells(); cells[0].focus(); }, 420);
      return;
    }
    if (status === 410) {
      stop("ttl");
      $("timer").classList.add("is-over");
      const text = data.reason === "used" ? "Этот код уже использован."
        : data.reason === "replaced" ? "Код заменён новым — используйте последний."
        : "Код истёк или недействителен. Запросите новый.";
      banner("code-banner", text, "warning");
      return;
    }
    if (status === 423) return showBlocked(data.retry_after);
    if (status === 429) {
      const wait = data.retry_after || 60;
      const target = banner("code-banner", `Слишком много проверок с вашего IP. Повторите через ${fmt(wait)}.`, "warning");
      countdown("ip", wait, (left) => {
        if (target.isConnected) target.textContent = left > 0
          ? `Слишком много проверок с вашего IP. Повторите через ${fmt(left)}.`
          : "Можно проверить код снова.";
      });
      return;
    }
    if (status === 422) return banner("code-banner", validation(data), "error");
    banner("code-banner", status === 0 ? "Нет соединения с сервером." : "Сервис временно недоступен.", "error");
  }

  // ------------------------------------------------------------ wiring
  $("phone-form").addEventListener("submit", (e) => { e.preventDefault(); sendCode(false); });
  $("code-form").addEventListener("submit", (e) => { e.preventDefault(); verify(); });
  $("resend-btn").addEventListener("click", () => sendCode(true));
  $("msisdn").addEventListener("input", () => { $("msisdn").classList.remove("is-error"); });
  $("back-btn").addEventListener("click", () => {
    stopAll();
    banner("code-banner", "");
    show("phone");
    setTimeout(() => $("msisdn").focus({ preventScroll: true }), 260);
  });
  document.querySelectorAll(".restart-btn").forEach((b) => b.addEventListener("click", () => {
    stopAll();
    clearCells();
    banner("phone-banner", "");
    banner("code-banner", "");
    $("msisdn").value = "";
    show("phone");
    setTimeout(() => $("msisdn").focus({ preventScroll: true }), 260);
  }));

  // ------------------------------------------------------------ attack demo
  const attempts = $("attempts");
  const TOTAL = 22;
  for (let i = 1; i <= TOTAL; i++) {
    const a = document.createElement("span");
    a.className = "attempt";
    a.textContent = i <= 20 ? String(i) : "429";
    attempts.append(a);
  }
  let attackTimer = null;

  function runAttack() {
    clearTimeout(attackTimer);
    const items = Array.from(attempts.children);
    items.forEach((a) => a.classList.remove("hit", "blocked"));
    $("attack-result").innerHTML = "&nbsp;";
    if (reduceMotion) {
      items.forEach((a, i) => a.classList.add(i < 20 ? "hit" : "blocked"));
      $("attack-result").innerHTML = "20 попыток прошли · дальше <strong>HTTP 429</strong> до конца минуты";
      return;
    }
    let i = 0;
    const step = () => {
      if (i >= TOTAL) {
        $("attack-result").innerHTML = "20 попыток прошли · дальше <strong>HTTP 429</strong> до конца минуты";
        return;
      }
      items[i].classList.add(i < 20 ? "hit" : "blocked");
      // accelerate through the allowed attempts, pause before the wall
      const delay = i < 19 ? 70 - i * 2 : 380;
      i += 1;
      attackTimer = setTimeout(step, delay);
    };
    step();
  }
  $("attack-replay").addEventListener("click", runAttack);
  if (io) io.observe($("attack")); else runAttack();
})();
