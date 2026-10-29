"use strict";
/* DomainManager frontend – no framework, no innerHTML with dynamic data. */

const state = { session: null, view: "overview", zones: null, zoneId: null, scanHosts: new Set(), lastScan: null, pollTimer: null };

// ------------------------------------------------------------------ helpers
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "checked" || k === "disabled" || k === "value" || k === "selected") el[k] = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const ICONS = {
  home: '<path d="M3 10.5 12 3l9 7.5V21h-6v-6H9v6H3z"/>',
  dns: '<path d="M4 4h16v6H4zM4 14h16v6H4z"/><circle cx="8" cy="7" r="1"/><circle cx="8" cy="17" r="1"/>',
  ddns: '<path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 4v5h-5"/>',
  shield: '<path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z"/><path d="m9 12 2 2 4-4"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 4v5h-5"/>',
  trash: '<path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  logout: '<path d="M9 21H5V3h4M16 17l5-5-5-5M21 12H9"/>',
  link: '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
};
function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.innerHTML = ICONS[name]; // static constant markup only
  return svg;
}
function logo() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 64 64");
  svg.innerHTML = '<path fill="#F38020" d="M50.5 27.6A15 15 0 0 0 21.6 22 11.5 11.5 0 0 0 4 32.5 10.5 10.5 0 0 0 14.5 45h35a9 9 0 0 0 1-17.4z"/><path fill="#FBAD41" d="M50.5 27.6c-.6 0-1.1 0-1.7.1L46 37.4a2 2 0 0 1-1.9 1.4H22.6l-.5 1.7a2 2 0 0 0 1.9 2.5h25.5a8 8 0 0 0 1-15.4z"/>';
  return svg;
}
function cloud(on) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 64 38");
  svg.innerHTML = '<path d="M50 14.5A14 14 0 0 0 23 9.6 10.8 10.8 0 0 0 6.5 19.5 9.8 9.8 0 0 0 16.3 31h33a8.3 8.3 0 0 0 .7-16.5z"/>';
  return h("span", { class: "proxy " + (on ? "on" : "off") }, svg, on ? "Proxied" : "Nur DNS");
}
// A cloud that toggles the proxy status on click, like in the Cloudflare dashboard.
function proxyButton(on, onToggle, disabled = false) {
  const btn = h("button", { class: "proxy-btn", type: "button", disabled,
    title: on ? "Klicken: nur DNS (IP öffentlich sichtbar)" : "Klicken: über Cloudflare proxien" }, cloud(on));
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try { await onToggle(!on); } catch (e) { toast(e.message, "error"); } finally { btn.disabled = false; }
  });
  return btn;
}
const SEV_LABEL = { critical: "Kritisch", high: "Hoch", medium: "Mittel", low: "Niedrig", info: "Info", ok: "OK" };
const sevBadge = (s) => h("span", { class: "badge sev-" + s }, SEV_LABEL[s] || s);
const fmtTime = (ts) => new Date(ts * 1000).toLocaleString("de-DE");

async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: { Accept: "application/json" }, credentials: "same-origin" };
  if (opts.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  if (init.method !== "GET" && state.session && state.session.csrf) init.headers["X-CSRF-Token"] = state.session.csrf;
  const res = await fetch(path, init);
  let data = null;
  try { data = await res.json(); } catch (_) { /* empty */ }
  if (res.status === 401 && path !== "/api/login") { state.session = null; renderLogin("Sitzung abgelaufen – bitte neu anmelden."); throw new Error("401"); }
  if (!res.ok) {
    let msg = (data && data.detail) || "HTTP " + res.status;
    if (Array.isArray(msg)) msg = msg.map((d) => d.msg).join("; ");
    throw new Error(msg);
  }
  return data;
}

// replaceChildren() would render null/false as text, so filter them first.
function put(el, ...children) {
  el.replaceChildren(...children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false));
}

function toast(msg, kind = "") {
  let box = document.querySelector(".toasts");
  if (!box) { box = h("div", { class: "toasts" }); document.body.append(box); }
  const t = h("div", { class: "toast " + kind }, msg);
  box.append(t);
  setTimeout(() => t.remove(), kind === "error" ? 7000 : 4000);
}

function modal({ title, body, confirmText = "OK", danger = false, wide = false, cancel = true, onConfirm }) {
  const close = () => ov.remove();
  const btn = h("button", { class: "btn " + (danger ? "danger solid" : "primary") }, confirmText);
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try { if ((await onConfirm()) !== false) close(); } catch (e) { toast(e.message, "error"); } finally { btn.disabled = false; }
  });
  const ov = h("div", { class: "overlay", onclick: (e) => { if (e.target === ov) close(); } },
    h("div", { class: "modal" + (wide ? " wide" : ""), role: "dialog", "aria-modal": "true" },
      h("div", { class: "card-head" }, h("h2", {}, title)),
      h("div", { class: "card-body" }, body),
      h("div", { class: "card-foot" }, h("span", { class: "spacer" }), cancel ? h("button", { class: "btn", onclick: close }, "Abbrechen") : null, btn)));
  document.body.append(ov);
  const first = ov.querySelector("input");
  (first || btn).focus();
  return { close, button: btn };
}

function errorBox(e) { return h("div", { class: "alert error" }, h("div", {}, h("b", {}, "Fehler"), e.message || String(e))); }
function loading() { return h("div", { class: "card" }, h("div", { class: "card-body" }, h("div", { class: "progress indeterminate" }, h("div")))); }

// ------------------------------------------------------------------ login
function renderLogin(notice) {
  stopPoll();
  const s = state.sessionInfo || {};
  const oidc = s.oidc || {};
  const err = h("div", { class: "alert error hidden" });
  const showError = (msg) => { err.replaceChildren(msg); err.classList.remove("hidden"); };
  const user = h("input", { type: "text", name: "username", autocomplete: "username", required: true, maxlength: "64" });
  const pass = h("input", { type: "password", name: "password", autocomplete: "current-password", required: true, maxlength: "256" });
  const otp = h("input", { type: "text", name: "otp", autocomplete: "one-time-code", inputmode: "numeric", pattern: "[0-9 ]*", maxlength: "10" });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Anmelden");
  const sso = oidc.enabled ? h("button", { class: "btn primary sso", type: "button",
    onclick: () => { location.assign("/api/oidc/login"); } }, icon("shield"), `Mit ${oidc.name} anmelden`) : null;
  const form = s.login_enabled ? h("form", { onsubmit: async (e) => {
    e.preventDefault();
    btn.disabled = true;
    err.classList.add("hidden");
    try {
      await api("/api/login", { method: "POST", body: { user: user.value, password: pass.value, otp: otp.value } });
      pass.value = "";
      await boot();
    } catch (ex) {
      showError(ex.message);
      pass.value = ""; otp.value = "";
    } finally { btn.disabled = false; }
  } },
    h("label", { class: "field" }, h("span", {}, "Benutzername"), user),
    h("label", { class: "field" }, h("span", {}, "Passwort"), pass),
    s.totp ? h("label", { class: "field" }, h("span", {}, "2FA-Code"), otp) : null,
    sso ? h("button", { class: "btn", type: "submit" }, "Mit Passwort anmelden") : btn) : null;
  const body = h("div", { class: "card-body" },
    notice ? h("div", { class: "alert info" }, notice) : null,
    !s.login_enabled && !oidc.enabled ? h("div", { class: "alert warn" }, h("div", {}, h("b", {}, "Login deaktiviert"), "Weder ADMIN_PASSWORD_HASH noch SSO (OIDC_*) ist konfiguriert. Siehe README.")) : null,
    err, sso, sso && form ? h("div", { class: "divider" }, "oder") : null, form);
  // Errors from the SSO callback arrive as ?login_error=… – show once, then clean the URL.
  const params = new URLSearchParams(location.search);
  if (params.get("login_error")) {
    showError(params.get("login_error"));
    history.replaceState(null, "", location.pathname + location.hash);
  }
  document.getElementById("app").replaceChildren(
    h("div", { class: "login-wrap" }, h("div", { class: "login" },
      h("div", { class: "brand" }, logo(), "DomainManager"),
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Anmelden")), body),
      h("div", { class: "foot" }, "Zugriff wird protokolliert."))));
  if (form) user.focus();
}

// ------------------------------------------------------------------ shell
const NAV = [
  ["overview", "Übersicht", "home"],
  ["dns", "DNS-Einträge", "dns"],
  ["ddns", "DDNS", "ddns"],
  ["usage", "NPM-Abgleich", "link"],
  ["scan", "Sicherheitscheck", "shield"],
  ["schedule", "Wochen-Scan", "clock"],
  ["audit", "Audit-Log", "list"],
];

function renderShell() {
  const s = state.session;
  const nav = h("nav", { class: "sidebar" }, h("div", { class: "nav-section" }, "Verwaltung"),
    NAV.map(([id, label, ic]) => h("a", { class: "nav-item" + (state.view === id ? " active" : ""), "data-view": id,
      onclick: () => go(id) }, icon(ic), label)));
  const logout = h("button", { class: "btn sm", title: "Abmelden", onclick: async () => {
    try { await api("/api/logout", { method: "POST" }); } catch (_) { /* ignore */ }
    state.session = null; renderLogin("Abgemeldet.");
  } }, icon("logout"), "Abmelden");
  document.getElementById("app").replaceChildren(
    h("header", { class: "topbar" }, h("div", { class: "brand" }, logo(), "DomainManager"), h("div", { class: "spacer" }),
      h("div", { class: "account" }, h("span", { class: "name" }, s.user), h("div", { class: "avatar" }, s.user.slice(0, 1).toUpperCase()), logout)),
    nav,
    h("main", { class: "main" }, h("div", { class: "page", id: "page" })));
  renderView();
}

function go(view) {
  if (state.view === view) return;
  state.view = view;
  history.replaceState(null, "", "#" + view);
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === view));
  stopPoll();
  renderView();
}
function stopPoll() { if (state.pollTimer) { clearTimeout(state.pollTimer); state.pollTimer = null; } }

function pageHead(title, desc, ...actions) {
  return h("div", { class: "page-head" }, h("div", {}, h("h1", {}, title), desc ? h("p", {}, desc) : null),
    actions.length ? h("div", { class: "actions" }, actions) : null);
}

function renderView() {
  const page = document.getElementById("page");
  if (!page) return;
  put(page, loading());
  const views = { overview: viewOverview, dns: viewDns, ddns: viewDdns, usage: viewUsage, scan: viewScan, schedule: viewSchedule, audit: viewAudit };
  (views[state.view] || viewOverview)(page).catch((e) => { if (e.message !== "401") put(page, errorBox(e)); });
}

async function getZones(force) {
  if (!state.zones || force) state.zones = await api("/api/zones");
  if (!state.zoneId && state.zones.length) state.zoneId = state.zones[0].id;
  return state.zones;
}

// ------------------------------------------------------------------ overview
async function viewOverview(page) {
  const st = await api("/api/status");
  const stat = (label, ok, value, hint) => h("div", { class: "stat" }, h("div", { class: "label" }, label),
    h("div", { class: "value" }, h("span", { class: "dot " + ok }), value), h("div", { class: "hint" }, hint));
  const cfS = st.cloudflare, ol = st.ollama, dd = st.ddns;
  const ipText = ["4", "6"].map((v) => dd.ip[v] ? `IPv${v} ${dd.ip[v]}` : null).filter(Boolean).join(" · ");
  const cards = h("div", { class: "grid" },
    stat("Cloudflare API", cfS.ok ? "ok" : "bad", cfS.ok ? "Verbunden" : "Fehler",
      cfS.ok ? (cfS.type === "token" ? "API-Token aktiv" : "Global API Key – besser einen eingeschränkten Token verwenden!") : cfS.error),
    stat("Ollama", ol.ok ? (ol.default_available ? "ok" : "warn") : "bad", ol.ok ? `${ol.models} Modelle` : "Nicht erreichbar",
      ol.ok ? (ol.default_available ? `Standard: ${ol.default_model}` : `Standardmodell ${ol.default_model} fehlt`) : `${ol.url} – ${ol.error}`),
    stat("DDNS-Updater", (HEALTH[dd.health] || HEALTH.error)[2],
      dd.health === "ok" ? `${dd.hosts} Hosts aktuell` : (HEALTH[dd.health] || HEALTH.error)[1],
      [dd.error, ipText || "Öffentliche IP noch nicht ermittelt", dd.last_run ? `Letzter Lauf ${fmtTime(dd.last_run)}` : null].filter(Boolean).join(" · ")),
    stat("Nginx Proxy Manager", !st.npm.configured ? "warn" : st.npm.error ? "bad" : st.npm.unused ? "warn" : "ok",
      !st.npm.configured ? "Nicht verbunden" : st.npm.error ? "Fehler" : st.npm.unused ? `${st.npm.unused} ungenutzte Subdomains` : "Alles genutzt",
      !st.npm.configured ? "NPM_URL in .env setzen" : st.npm.error || (st.npm.generated ? `${st.npm.hosts} Hosts · Stand ${fmtTime(st.npm.generated)}` : "Noch nicht geprüft")),
    stat("Wochen-Scan", st.schedule.enabled ? "ok" : "warn", st.schedule.enabled ? `${st.schedule.tested} Hosts geprüft` : "Aus",
      st.schedule.summary_score != null ? `Letzter Durchgang: Score ${st.schedule.summary_score}/100` : "Noch kein vollständiger Durchgang"));

  const zoneCard = h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Domains"), h("span", { class: "sub" }, "Zonen in deinem Cloudflare-Konto")));
  put(page, pageHead("Übersicht", "Status aller angebundenen Dienste und deine Cloudflare-Zonen.",
    h("button", { class: "btn", onclick: () => { state.zones = null; renderView(); } }, icon("refresh"), "Aktualisieren")), cards, zoneCard);
  if (!cfS.ok) { zoneCard.append(h("div", { class: "empty" }, "Cloudflare nicht verbunden.")); return; }
  const zones = await getZones(true);
  zoneCard.append(h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, h("th", {}, "Domain"), h("th", {}, "Status"), h("th", {}, "Plan"), h("th", {}, "Nameserver"), h("th", {}))),
    h("tbody", {}, zones.map((z) => h("tr", {},
      h("td", { class: "name" }, z.name),
      h("td", {}, h("span", { class: "badge " + (z.status === "active" ? "sev-ok" : "sev-medium") }, z.status === "active" ? "Aktiv" : z.status)),
      h("td", {}, z.plan || "–"),
      h("td", { class: "content" }, z.name_servers.join(", ")),
      h("td", { class: "actions" }, h("button", { class: "btn sm", onclick: () => { state.zoneId = z.id; go("dns"); } }, "DNS verwalten"))))))));
}

// ------------------------------------------------------------------ dns
async function viewDns(page, force = false) {
  const zones = await getZones();
  if (!zones.length) { put(page, pageHead("DNS-Einträge"), h("div", { class: "card" }, h("div", { class: "empty" }, "Keine Zonen gefunden."))); return; }
  const records = await api(`/api/zones/${state.zoneId}/records${force ? "?refresh=true" : ""}`);
  const zone = zones.find((z) => z.id === state.zoneId);
  const select = h("select", { onchange: (e) => { state.zoneId = e.target.value; renderView(); } },
    zones.map((z) => h("option", { value: z.id, selected: z.id === state.zoneId }, z.name)));
  const search = h("input", { type: "search", placeholder: "Suchen (Name, Inhalt, Typ)…" });
  const typeSel = h("select", {}, h("option", { value: "" }, "Alle Typen"),
    [...new Set(records.map((r) => r.type))].sort().map((t) => h("option", { value: t }, t)));
  const tbody = h("tbody");
  const allowDelete = state.session.allow_dns_delete;

  function draw() {
    const q = search.value.trim().toLowerCase(), t = typeSel.value;
    const rows = records.filter((r) => (!t || r.type === t) && (!q || (r.name + " " + r.content + " " + r.type).toLowerCase().includes(q)));
    tbody.replaceChildren(...(rows.length ? rows.map((r) => h("tr", {},
      h("td", {}, h("span", { class: "badge type" }, r.type)),
      h("td", { class: "name" }, r.name, r.in_ddns ? [" ", h("span", { class: "badge ddns", title: "Wird von cloudflare-ddns aktualisiert" }, "DDNS")] : null),
      h("td", { class: "content", title: r.content }, r.content),
      h("td", {}, r.proxiable ? proxyButton(r.proxied, async (next) => {
        await api(`/api/zones/${zone.id}/records/${r.id}`, { method: "PATCH", body: { proxied: next } });
        r.proxied = next;
        toast(`${r.name}: ${next ? "Proxy aktiviert" : "nur DNS"}`, "ok");
        draw();
      }) : h("span", { class: "muted small" }, "–")),
      h("td", { class: "nowrap" }, r.ttl === 1 ? "Auto" : r.ttl + " s"),
      h("td", { class: "actions" },
        ["A", "AAAA", "CNAME"].includes(r.type) ? h("button", { class: "btn sm link", onclick: () => { state.scanHosts.add(r.name); toast(`${r.name} zum Sicherheitscheck hinzugefügt`, "ok"); } }, "Prüfen") : null,
        allowDelete ? h("button", { class: "btn sm danger", title: "Record löschen", onclick: () => confirmDeleteRecord(zone, r, () => viewDns(page)) }, icon("trash")) : null)))
      : [h("tr", {}, h("td", { colspan: "6", class: "empty" }, "Keine Einträge."))]));
  }
  search.addEventListener("input", draw);
  typeSel.addEventListener("change", draw);
  draw();

  put(page, 
    pageHead("DNS-Einträge", "DNS-Records der gewählten Zone. Orange Wolke = über Cloudflare-Proxy, graue Wolke = IP öffentlich sichtbar.",
      select, h("button", { class: "btn", onclick: () => viewDns(page, true).catch((e) => toast(e.message, "error")) }, icon("refresh"), "Neu laden")),
    !allowDelete ? h("div", { class: "alert info" }, h("div", {}, "Löschen von DNS-Records ist deaktiviert. Zum Aktivieren ", h("code", {}, "ALLOW_DNS_DELETE=true"), " setzen.")) : null,
    h("div", { class: "card" },
      h("div", { class: "card-head" }, h("h2", {}, zone.name), h("span", { class: "sub" }, `${records.length} Einträge`),
        h("div", { class: "right" }, typeSel, search)),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Typ"), h("th", {}, "Name"), h("th", {}, "Inhalt"), h("th", {}, "Proxy-Status"), h("th", {}, "TTL"), h("th", {}))),
        tbody))));
}

function confirmDeleteRecord(zone, r, after) {
  const input = h("input", { type: "text", placeholder: r.name, autocomplete: "off" });
  modal({
    title: "DNS-Record löschen", danger: true, confirmText: "Endgültig löschen",
    body: [h("p", {}, "Der folgende Record wird bei Cloudflare gelöscht:"),
      h("p", {}, h("span", { class: "badge type" }, r.type), " ", h("b", {}, r.name), " → ", h("code", {}, r.content)),
      r.in_ddns ? h("div", { class: "alert warn" }, "Dieser Host wird vom DDNS-Updater verwaltet und würde beim nächsten Lauf wieder angelegt. Zuerst unter „DDNS“ entfernen.") : null,
      h("label", { class: "field" }, h("span", {}, "Zur Bestätigung den Namen eintippen"), input)],
    onConfirm: async () => {
      await api(`/api/zones/${zone.id}/records/${r.id}`, { method: "DELETE", body: { confirm: input.value } });
      toast(`${r.name} gelöscht`, "ok");
      after();
    },
  });
}

// ------------------------------------------------------------------ ddns
const HEALTH = {
  ok: ["sev-ok", "Aktiv", "ok"], starting: ["sev-low", "Startet…", "warn"], paused: ["sev-medium", "Pausiert", "warn"],
  no_hosts: ["sev-medium", "Keine Hosts", "warn"], stalled: ["sev-high", "Hängt – siehe Diagnose", "bad"], error: ["sev-high", "Fehler", "bad"],
};
const TTL_LABEL = (t) => (t === 1 ? "Auto" : t < 60 ? `${t} s` : t < 3600 ? `${t / 60} min` : `${t / 3600} h`);
const fmtAgo = (ts) => {
  if (!ts) return "–";
  const d = Math.round(Date.now() / 1000 - ts);
  return d < 60 ? `vor ${d} s` : d < 3600 ? `vor ${Math.round(d / 60)} min` : fmtTime(ts);
};

function toggle(checked, onChange, label) {
  const input = h("input", { type: "checkbox", checked, role: "switch" });
  input.addEventListener("change", () => onChange(input.checked, input));
  return h("label", { class: "switch" }, input, h("span", { class: "slider" }), label ? h("span", {}, label) : null);
}

async function viewDdns(page) {
  const d = await api("/api/ddns");
  const s = d.settings, st = d.state;
  const reload = () => viewDdns(page).catch((e) => toast(e.message, "error"));

  async function saveSettings(patch) {
    try {
      await api("/api/ddns/settings", { method: "PUT", body: { ...s, ...patch } });
      Object.assign(s, patch);
      toast("Einstellungen gespeichert", "ok");
    } catch (e) { toast(e.message, "error"); }
    reload();
  }
  async function saveHost(host, patch) {
    const body = { name: host.name, ipv4: host.ipv4, ipv6: host.ipv6, proxied: host.proxied, ttl: host.ttl, enabled: host.enabled, ...patch };
    await api("/api/ddns/hosts", { method: "PUT", body });
    Object.assign(host, patch);
    toast(`${host.name} gespeichert – wird beim nächsten Lauf übernommen`, "ok");
    reload();
  }

  // ---- status / settings
  const runBtn = h("button", { class: "btn", disabled: st.running }, icon("refresh"), st.running ? "Läuft…" : "Jetzt aktualisieren");
  runBtn.addEventListener("click", async () => {
    runBtn.disabled = true;
    try { await api("/api/ddns/run", { method: "POST" }); toast("Aktualisierung abgeschlossen", "ok"); } catch (e) { toast(e.message, "error"); }
    reload();
  });
  const intervalSel = h("select", { onchange: (e) => saveSettings({ interval: Number(e.target.value) }) },
    [60, 120, 300, 600, 900, 1800, 3600].map((v) => h("option", { value: v, selected: v === s.interval }, `alle ${v / 60} min`)));
  const ipLine = (v) => {
    const on = s[`ipv${v}`];
    const ip = st.ip[v], err = st.ip_error[v];
    return h("div", { class: "ip-line" },
      toggle(on, (val) => saveSettings({ [`ipv${v}`]: val }), `IPv${v}`),
      !on ? h("span", { class: "muted small" }, "deaktiviert")
        : ip ? h("code", { class: "ip" }, ip)
        : err ? h("span", { class: "badge sev-high", title: err }, "nicht ermittelbar")
        : h("span", { class: "muted small" }, "noch nicht ermittelt"));
  };
  const statusCard = h("div", { class: "card" },
    h("div", { class: "card-head" }, h("h2", {}, "DDNS-Updater"),
      h("span", { class: "badge " + (HEALTH[st.health] || HEALTH.error)[0] }, (HEALTH[st.health] || HEALTH.error)[1]),
      st.error && st.health !== "paused" ? h("span", { class: "sub" }, st.error) : null,
      h("div", { class: "right" }, toggle(s.enabled, (val) => saveSettings({ enabled: val }), s.enabled ? "Ein" : "Aus"), intervalSel, runBtn,
        h("button", { class: "btn", onclick: diagnoseDialog }, "Diagnose"))),
    h("div", { class: "card-body ddns-status" },
      h("div", {}, h("div", { class: "label" }, "Öffentliche IP"), ipLine(4), ipLine(6)),
      h("div", {}, h("div", { class: "label" }, "Letzter Lauf"), h("div", {}, fmtAgo(st.last_run))),
      h("div", {}, h("div", { class: "label" }, "Nächster Lauf"), h("div", {}, s.enabled && st.next_run ? fmtTime(st.next_run) : "–")),
      h("div", {}, h("div", { class: "label" }, "Benachrichtigung"), h("div", {}, d.notify ? "aktiv (NOTIFY_URL)" : h("span", { class: "muted" }, "aus")))));

  // ---- hosts table
  const addName = h("input", { type: "text", placeholder: "sub.deinedomain.de", autocomplete: "off" });
  const addV4 = h("input", { type: "checkbox", checked: true });
  const addV6 = h("input", { type: "checkbox", checked: s.ipv6 });
  const addProxy = h("input", { type: "checkbox", checked: true });
  const doAdd = async () => {
    const name = addName.value.trim().toLowerCase().replace(/\.$/, "");
    if (!name) return;
    try {
      await api("/api/ddns/hosts", { method: "POST", body: { name, ipv4: addV4.checked, ipv6: addV6.checked, proxied: addProxy.checked, ttl: 1 } });
      toast(`${name} hinzugefügt`, "ok");
      reload();
    } catch (e) { toast(e.message, "error"); }
  };
  addName.addEventListener("keydown", (e) => { if (e.key === "Enter") doAdd(); });

  const rows = d.hosts.map((host) => {
    const recs = host.records || [];
    const status = host.status;
    const ttlSel = h("select", { class: "sm", disabled: host.proxied, title: host.proxied ? "Bei Proxy setzt Cloudflare die TTL automatisch" : "" },
      d.ttl_choices.map((t) => h("option", { value: t, selected: t === host.ttl }, TTL_LABEL(t))));
    ttlSel.addEventListener("change", () => saveHost(host, { ttl: Number(ttlSel.value) }).catch((e) => toast(e.message, "error")));
    const fam = (v) => {
      const cb = h("input", { type: "checkbox", checked: host[`ipv${v}`], title: `IPv${v} (${v === 4 ? "A" : "AAAA"}-Record) pflegen` });
      cb.addEventListener("change", () => saveHost(host, { [`ipv${v}`]: cb.checked }).catch((e) => { cb.checked = !cb.checked; toast(e.message, "error"); }));
      return cb;
    };
    return h("tr", { class: host.enabled ? "" : "muted" },
      h("td", { class: "name" }, host.name, !host.enabled ? [" ", h("span", { class: "badge sev-info" }, "pausiert")] : null),
      h("td", { class: "center" }, fam(4)),
      h("td", { class: "center" }, fam(6)),
      h("td", {}, proxyButton(host.proxied, (next) => saveHost(host, { proxied: next }))),
      h("td", {}, ttlSel),
      h("td", { class: "content", title: recs.map((r) => `${r.type} ${r.content}`).join(", ") },
        recs.length ? recs.map((r) => `${r.type} ${r.content}`).join(", ") : h("span", { class: "muted" }, "wird angelegt")),
      h("td", { class: "small" }, !status ? h("span", { class: "muted" }, "noch nicht geprüft")
        : h("span", { title: status.msgs.join("\n") }, h("span", { class: "dot " + (status.ok ? "ok" : "bad") }), " ", status.msgs.join(" · "),
          h("div", { class: "muted" }, fmtAgo(status.ts)))),
      h("td", { class: "actions" },
        h("button", { class: "btn sm", onclick: () => saveHost(host, { enabled: !host.enabled }).catch((e) => toast(e.message, "error")) }, host.enabled ? "Pausieren" : "Fortsetzen"),
        " ",
        h("button", { class: "btn sm danger", title: "Aus DDNS entfernen", onclick: () => confirmRemoveHost(host, reload) }, icon("trash"))));
  });

  const hostCard = h("div", { class: "card" },
    h("div", { class: "card-head" }, h("h2", {}, "Hosts"), h("span", { class: "sub" }, `${d.hosts.length} verwaltet`),
      h("div", { class: "right add-host" }, addName,
        h("label", { class: "check small" }, addV4, "IPv4"), h("label", { class: "check small" }, addV6, "IPv6"),
        h("label", { class: "check small" }, addProxy, "Proxy"),
        h("button", { class: "btn sm", onclick: doAdd }, icon("plus"), "Hinzufügen"))),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Hostname"), h("th", { class: "center" }, "IPv4"), h("th", { class: "center" }, "IPv6"),
        h("th", {}, "Proxy"), h("th", {}, "TTL"), h("th", {}, "Record bei Cloudflare"), h("th", {}, "Status"), h("th", {}))),
      h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colspan: "8", class: "empty" },
        "Noch keine Hosts. Über „Importieren“ deine Subdomains aus favonia übernehmen oder oben einzeln hinzufügen."))))));

  const logCard = h("div", { class: "card" },
    h("div", { class: "card-head" }, h("h2", {}, "Protokoll"), h("span", { class: "sub" }, "Die letzten Läufe – auch in „docker compose logs“")),
    d.log.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Zeit"), h("th", {}, "Auslöser"), h("th", {}, "IP"), h("th", {}, "Ergebnis"))),
      h("tbody", {}, d.log.map((e) => h("tr", {},
        h("td", { class: "nowrap small" }, fmtTime(e.ts)),
        h("td", { class: "small" }, e.reason === "manual" ? "manuell" : "automatisch"),
        h("td", { class: "mono small" }, Object.entries(e.ip).map(([v, ip]) => `v${v} ${ip}`).join(" · ") || "–"),
        h("td", { class: "small" },
          h("div", {}, h("span", { class: "dot " + (e.errors.length ? "bad" : "ok") }), " ",
            `${e.changes.length} geändert · ${e.unchanged} aktuell · ${e.errors.length} Fehler`),
          e.changes.map((x) => h("div", { class: "muted" }, "✎ " + x)),
          e.errors.map((x) => h("div", { class: "err-line" }, "✕ " + x))))))))
      : h("div", { class: "empty" }, s.enabled ? "Noch kein Lauf seit dem Start." : "Updater ist pausiert."));

  const historyCard = h("div", { class: "card" },
    h("div", { class: "card-head" }, h("h2", {}, "IP-Verlauf"), h("span", { class: "sub" }, "Wechsel deiner öffentlichen IP")),
    d.history.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Zeit"), h("th", {}, "Typ"), h("th", {}, "Alt"), h("th", {}, "Neu"))),
      h("tbody", {}, d.history.map((x) => h("tr", {}, h("td", { class: "nowrap small" }, fmtTime(x.ts)), h("td", {}, `IPv${x.version}`),
        h("td", { class: "content" }, x.old || "–"), h("td", { class: "content" }, x.new))))))
      : h("div", { class: "empty" }, "Noch keine Einträge."));

  put(page,
    pageHead("DDNS", "Der eingebaute Updater hält die A/AAAA-Records deiner Hosts auf deiner aktuellen öffentlichen IP – inkl. Proxy-Status und TTL. favonia/cloudflare-ddns wird damit nicht mehr gebraucht.",
      h("button", { class: "btn primary", onclick: () => importDialog(reload) }, icon("plus"), "Importieren")),
    d.cf_error ? h("div", { class: "alert error" }, d.cf_error) : null,
    !s.enabled ? h("div", { class: "alert warn" }, h("div", {}, h("b", {}, "Updater ist pausiert"),
      "Ablauf beim Umstieg: 1. Hosts importieren und Proxy-Einstellungen prüfen · 2. favonia-Container stoppen (",
      h("code", {}, "docker compose down"), " im CloudflareDNS-Ordner) · 3. hier einschalten. Laufen beide gleichzeitig, setzt favonia seine Proxy-Einstellungen zurück.")) : null,
    s.enabled && st.ip_error && st.ip_error["6"] && s.ipv6 ? h("div", { class: "alert warn" }, h("div", {}, h("b", {}, "IPv6 nicht ermittelbar"),
      "Der Container hat kein IPv6. Entweder IPv6 hier ausschalten oder im Docker-Netz aktivieren (siehe README).")) : null,
    statusCard, hostCard, logCard, historyCard);
}

async function diagnoseDialog() {
  const box = h("div", {}, h("div", { class: "progress indeterminate" }, h("div")), h("p", { class: "small muted" }, "Prüfe IP-Dienste und Cloudflare … (bis zu 30 s)"));
  modal({ title: "DDNS-Diagnose", wide: true, cancel: false, confirmText: "Schließen", onConfirm: () => true, body: box });
  try {
    const d = await api("/api/ddns/diagnose", { method: "POST" });
    const ok = (b) => h("span", { class: "dot " + (b ? "ok" : "bad") });
    const cfd = d.cloudflare;
    put(box,
      h("h3", {}, "Öffentliche IP"),
      h("div", { class: "table-wrap import-table" }, h("table", {}, h("tbody", {}, d.providers.map((p) => h("tr", {},
        h("td", {}, ok(!!p.ip)), h("td", { class: "small" }, `IPv${p.version}`), h("td", { class: "mono small" }, p.url),
        h("td", { class: "small" }, p.ip ? h("code", {}, p.ip) : h("span", { class: "err-line" }, p.info))))))),
      h("p", { class: "small muted" }, "Schlagen alle IPv4-Dienste fehl, hat der Container keinen Internetzugang (Firewall, DNS, Docker-Netz). IPv6-Fehler sind normal, solange IPv6 im Docker-Netz nicht aktiviert ist."),
      h("h3", {}, "Cloudflare"),
      h("p", {}, ok(cfd.ok), " ", cfd.ok ? `Token gültig (${cfd.type}) · Zonen: ${(cfd.zones || []).join(", ") || "keine"}` : cfd.error),
      d.write_test ? h("p", {}, ok(d.write_test.ok), " Schreibtest an ", h("code", {}, d.write_test.record), " (ohne Änderung): ",
        d.write_test.ok ? "erlaubt" : h("span", { class: "err-line" }, `${d.write_test.error} → Token braucht „Zone → DNS → Edit“`))
        : cfd.ok ? h("p", { class: "small muted" }, "Kein Schreibtest möglich – es gibt noch keinen bestehenden A/AAAA-Record eines verwalteten Hosts.") : null);
  } catch (e) { put(box, errorBox(e)); }
}

function confirmRemoveHost(host, after) {
  const del = h("input", { type: "checkbox" });
  const hasRecs = (host.records || []).length > 0;
  modal({
    title: "Host aus DDNS entfernen", danger: true, confirmText: "Entfernen",
    body: [h("p", {}, h("b", {}, host.name), " wird nicht mehr automatisch aktualisiert."),
      hasRecs && state.session.allow_dns_delete ? h("label", { class: "check" }, del, `Auch die ${host.records.length} A/AAAA-Record(s) bei Cloudflare löschen`)
        : hasRecs ? h("div", { class: "alert info small" }, "Der DNS-Record bleibt bei Cloudflare mit der letzten IP bestehen. (Löschen erfordert ALLOW_DNS_DELETE=true.)") : null],
    onConfirm: async () => {
      const res = await api("/api/ddns/hosts", { method: "DELETE", body: { name: host.name, delete_records: del.checked } });
      toast(`${host.name} entfernt${res.deleted.length ? ` (${res.deleted.length} Record(s) gelöscht)` : ""}`, "ok");
      after();
    },
  });
}

function importDialog(after) {
  const tabs = h("div", { class: "tabs" });
  const pane = h("div");
  let candidates = [];
  const m = modal({ title: "Hosts importieren", wide: true, confirmText: "Importieren", body: [tabs, pane],
    onConfirm: async () => {
      const chosen = candidates.filter((c) => c.selected);
      if (!chosen.length) { toast("Nichts ausgewählt", "error"); return false; }
      const res = await api("/api/ddns/import", { method: "POST", body: { hosts: chosen.map((c) => ({ name: c.name, ipv4: c.ipv4, ipv6: c.ipv6, proxied: c.proxied, ttl: 1 })) } });
      toast(`${res.added.length} importiert${res.skipped.length ? `, ${res.skipped.length} übersprungen` : ""}`, "ok");
      after();
    } });
  m.button.disabled = true;

  function showCandidates(list, note) {
    candidates = list.map((c) => ({ ...c, selected: !c.managed && !!c.zone && (c.ipv4 || c.ipv6) }));
    const count = h("span", { class: "small muted" });
    const update = () => {
      const n = candidates.filter((c) => c.selected).length;
      count.textContent = `${n} ausgewählt`;
      m.button.disabled = !n;
      m.button.textContent = n ? `${n} importieren` : "Importieren";
    };
    const rows = candidates.map((c) => {
      const usable = !c.managed && !!c.zone;
      const sel = h("input", { type: "checkbox", checked: c.selected, disabled: !usable });
      sel.addEventListener("change", () => { c.selected = sel.checked; update(); });
      const fam = (k) => { const cb = h("input", { type: "checkbox", checked: c[k], disabled: !usable }); cb.addEventListener("change", () => { c[k] = cb.checked; }); return cb; };
      const proxyCell = h("td");
      const drawProxy = () => proxyCell.replaceChildren(proxyButton(c.proxied, async (next) => { c.proxied = next; drawProxy(); }, !usable));
      drawProxy();
      return h("tr", { class: usable ? "" : "muted" },
        h("td", {}, sel), h("td", { class: "name" }, c.name),
        h("td", { class: "center" }, fam("ipv4")), h("td", { class: "center" }, fam("ipv6")), proxyCell,
        h("td", { class: "content small" }, c.records.length ? c.records.map((r) => `${r.type} ${r.content}`).join(", ") : "neu"),
        h("td", { class: "small" }, c.managed ? "bereits verwaltet" : !c.zone ? h("span", { class: "badge sev-high" }, "keine Zone") : c.zone));
    });
    put(pane, note,
      rows.length ? [h("div", { class: "toolbar" }, count), h("div", { class: "table-wrap import-table" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}), h("th", {}, "Hostname"), h("th", { class: "center" }, "IPv4"), h("th", { class: "center" }, "IPv6"),
          h("th", {}, "Proxy"), h("th", {}, "Aktuell"), h("th", {}, "Zone"))), h("tbody", {}, rows)))]
        : h("div", { class: "empty" }, "Keine Hosts gefunden."));
    update();
  }

  function select(tab) {
    tabs.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
    candidates = []; m.button.disabled = true;
    if (tab === "paste") {
      const ta = h("textarea", { rows: "7", placeholder: "Inhalt deiner favonia docker-compose.yml / .env einfügen, z.B.\nDOMAINS=example.org,www.example.org\nPROXIED=true\n\n…oder einfach eine Liste von Hostnamen." });
      const go = h("button", { class: "btn" }, "Auslesen");
      go.addEventListener("click", async () => {
        go.disabled = true;
        try {
          const res = await api("/api/ddns/import/parse", { method: "POST", body: { text: ta.value } });
          showCandidates(res.candidates, [ta, h("div", { class: "toolbar" }, go), parseNote(res)]);
        } catch (e) { toast(e.message, "error"); } finally { go.disabled = false; }
      });
      put(pane, h("p", { class: "small muted" }, "Tokens o.Ä. werden ignoriert – ausgelesen werden nur DOMAINS, IP4_DOMAINS, IP6_DOMAINS und PROXIED. Der Text wird nicht gespeichert."), ta, h("div", { class: "toolbar" }, go));
      return;
    }
    put(pane, h("div", { class: "progress indeterminate" }, h("div")));
    sources.then((src) => {
      if (tab === "folder") {
        const f = src.folder;
        if (!f.available) {
          put(pane, h("div", { class: "alert info" }, h("div", {}, h("b", {}, "Kein favonia-Ordner eingebunden"),
            "In .env ", h("code", {}, "DDNS_IMPORT_DIR"), " auf deinen CloudflareDNS-Ordner setzen und neu starten – oder den Tab „Einfügen“ nutzen.")));
          return;
        }
        showCandidates(f.candidates, h("p", { class: "small muted" }, `Gelesen: ${f.files.join(", ") || "keine passenden Dateien"}. `, parseNote(f)));
      } else {
        const ipTxt = Object.entries(src.ip).map(([v, ip]) => `IPv${v} ${ip}`).join(", ");
        showCandidates(src.suggestions, h("p", { class: "small muted" }, ipTxt
          ? `Alle A/AAAA-Records, die gerade auf deine öffentliche IP zeigen (${ipTxt}) – vermutlich deine bisherigen DDNS-Hosts.`
          : "Öffentliche IP konnte nicht ermittelt werden."));
      }
    }).catch((e) => put(pane, errorBox(e)));
  }
  const parseNote = (res) => [
    res.proxied_expr ? h("div", { class: "alert info small" }, "favonia nutzt einen PROXIED-Ausdruck. Der Proxy-Status wurde daher vom aktuellen Record übernommen – bitte prüfen.") : null,
    res.invalid ? h("div", { class: "alert warn small" }, `${res.invalid} Eintrag/Einträge waren kein gültiger Hostname und wurden ignoriert.`) : null,
  ];
  const sources = api("/api/ddns/import");
  for (const [id, label] of [["folder", "Aus favonia-Ordner"], ["suggest", "Vorschläge aus Cloudflare"], ["paste", "Einfügen"]])
    tabs.append(h("button", { class: "tab", type: "button", "data-tab": id, onclick: () => select(id) }, label));
  select("folder");
}

// ------------------------------------------------------------------ scan
async function viewScan(page) {
  const [zones, recordsByZone, modelsRes] = await Promise.all([
    getZones(),
    getZones().then((zs) => Promise.all(zs.map((z) => api(`/api/zones/${z.id}/records`).then((r) => [z, r])))),
    api("/api/ollama/models").catch((e) => ({ error: e.message, models: [] })),
  ]);
  const max = state.session.max_scan_hosts;
  const hostsByZone = recordsByZone.map(([z, recs]) => {
    const m = new Map();
    for (const r of recs) if (["A", "AAAA", "CNAME"].includes(r.type)) {
      const e = m.get(r.name) || { name: r.name, types: new Set(), proxied: true, ddns: r.in_ddns };
      e.types.add(r.type); e.proxied = e.proxied && r.proxied; m.set(r.name, e);
    }
    return [z, [...m.values()].sort((a, b) => a.name.localeCompare(b.name))];
  });
  const counter = h("span", { class: "sub" });
  const startBtn = h("button", { class: "btn primary" }, icon("shield"), "Scan starten");
  const updateCount = () => {
    counter.textContent = `${state.scanHosts.size} ausgewählt (max. ${max})`;
    startBtn.disabled = !state.scanHosts.size || state.scanHosts.size > max;
  };
  const boxes = [];
  const list = h("div", { class: "host-list" }, hostsByZone.map(([z, hosts]) => {
    const groupBox = h("input", { type: "checkbox" });
    const rows = hosts.map((x) => {
      const cb = h("input", { type: "checkbox", checked: state.scanHosts.has(x.name) });
      cb.addEventListener("change", () => { cb.checked ? state.scanHosts.add(x.name) : state.scanHosts.delete(x.name); updateCount(); });
      boxes.push([cb, x]);
      return h("label", { class: "host-row" }, cb, h("span", {}, x.name),
        h("span", { class: "rt" }, x.ddns ? h("span", { class: "badge ddns" }, "DDNS") : null, [...x.types].map((t) => h("span", { class: "badge type" }, t)), cloud(x.proxied)));
    });
    groupBox.addEventListener("change", () => {
      for (const [cb, x] of boxes) if (hosts.includes(x)) { cb.checked = groupBox.checked; groupBox.checked ? state.scanHosts.add(x.name) : state.scanHosts.delete(x.name); }
      updateCount();
    });
    return [h("label", { class: "host-group" }, groupBox, z.name, h("span", { class: "muted small" }, `${hosts.length} Hosts`)), rows];
  }));
  const selectWhere = (pred) => { for (const [cb, x] of boxes) { cb.checked = pred(x); cb.checked ? state.scanHosts.add(x.name) : state.scanHosts.delete(x.name); } updateCount(); };

  const usable = (modelsRes.models || []).filter((m) => m.usable);
  const modelSel = h("select", {}, usable.map((m) => h("option", { value: m.name, selected: m.name === modelsRes.default },
    `${m.name} · ${m.size_gb} GB${m.params ? " · " + m.params : ""}${m.name === modelsRes.default ? " (Standard)" : ""}`)));
  const aiBox = h("input", { type: "checkbox", checked: usable.length > 0, disabled: usable.length === 0 });
  const result = h("div");

  startBtn.addEventListener("click", async () => {
    startBtn.disabled = true;
    try {
      const { id } = await api("/api/scan", { method: "POST", body: { hosts: [...state.scanHosts], model: modelSel.value || "", ai: aiBox.checked } });
      state.lastScan = id;
      pollScan(id, result, () => updateCount());
    } catch (e) { toast(e.message, "error"); updateCount(); }
  });

  put(page, 
    pageHead("Sicherheitscheck", "Prüft DNS, Cloudflare-Zoneneinstellungen, TLS, HTTPS-Weiterleitung, Security-Header und E-Mail-Schutz deterministisch. Das lokale Ollama-Modell fasst die Befunde zusammen und priorisiert Maßnahmen."),
    h("div", { class: "card" },
      h("div", { class: "card-head" }, h("h2", {}, "Hosts auswählen"), counter,
        h("div", { class: "right" },
          h("button", { class: "btn sm", onclick: () => selectWhere((x) => x.ddns) }, "Alle DDNS-Hosts"),
          h("button", { class: "btn sm", onclick: () => selectWhere((x) => !x.proxied) }, "Alle ohne Proxy"),
          h("button", { class: "btn sm", onclick: () => selectWhere(() => false) }, "Keine"))),
      h("div", { class: "card-body" }, list),
      h("div", { class: "card-foot" },
        h("label", { class: "check" }, aiBox, "KI-Auswertung mit"), modelSel,
        modelsRes.error ? h("span", { class: "small muted" }, `(${modelsRes.error})`) : null,
        h("span", { class: "spacer" }), startBtn)),
    result);
  updateCount();
  if (state.lastScan) pollScan(state.lastScan, result, () => updateCount());
}

function pollScan(id, box, onDone) {
  stopPoll();
  const tick = async () => {
    let job;
    try { job = await api(`/api/scan/${id}`); } catch (e) { if (e.message !== "401") put(box, errorBox(e)); return; }
    if (job.status === "running") {
      const p = job.progress || { done: 0, total: 1 };
      const bar = h("div", { class: "progress" + (job.phase === "ai" ? " indeterminate" : "") }, h("div"));
      if (job.phase !== "ai") bar.firstChild.style.width = Math.round((100 * p.done) / Math.max(p.total, 1)) + "%";
      put(box, h("div", { class: "card" }, h("div", { class: "card-body" },
        h("p", {}, job.phase === "ai" ? `KI-Auswertung läuft mit ${job.model} … (Modell wird ggf. erst in den VRAM geladen)` : `Prüfungen laufen … ${p.done}/${p.total}`), bar)));
      state.pollTimer = setTimeout(tick, 1500);
      return;
    }
    onDone();
    renderScanResult(job, box);
  };
  tick();
}

function renderScanResult(job, box) {
  if (job.status === "error") { put(box, errorBox(new Error(job.error))); return; }
  const r = job.result;
  const cls = r.score >= 80 ? "good" : r.score >= 50 ? "mid" : "bad";
  const filterSel = h("select", {}, h("option", { value: "problems" }, "Nur Probleme"), h("option", { value: "all" }, "Alle Befunde"));
  const tbody = h("tbody");
  const draw = () => {
    const rows = r.findings.filter((f) => filterSel.value === "all" || !["ok", "info"].includes(f.severity));
    tbody.replaceChildren(...(rows.length ? rows.map((f) => h("tr", {}, h("td", {}, sevBadge(f.severity)), h("td", { class: "name" }, f.host),
      h("td", {}, h("div", {}, h("b", {}, f.title)), f.detail ? h("div", { class: "muted small" }, f.detail) : null), h("td", { class: "muted small" }, f.check)))
      : [h("tr", {}, h("td", { colspan: "4", class: "empty" }, "Keine Probleme gefunden 🎉"))]));
  };
  filterSel.addEventListener("change", draw);
  draw();

  let aiCard = null;
  if (job.ai) {
    const a = job.ai;
    const riskSev = { niedrig: "low", mittel: "medium", hoch: "high", kritisch: "critical" }[a.risiko] || "info";
    aiCard = h("div", { class: "card" },
      h("div", { class: "card-head" }, h("h2", {}, "KI-Einschätzung"), h("span", { class: "badge sev-" + riskSev }, "Risiko: " + a.risiko),
        h("span", { class: "sub right" }, `${a.model} · ${a.eval_seconds}s`)),
      h("div", { class: "card-body" }, h("p", {}, a.zusammenfassung),
        h("p", { class: "muted small" }, "Die Einschätzung stammt von einem kleinen lokalen Modell und kann Fehler enthalten. Maßgeblich sind die Befunde unten.")),
      a.massnahmen.length ? h("ol", { class: "steps" }, a.massnahmen.map((m) => h("li", {}, h("div", { class: "t" }, m.titel), h("div", { class: "b" }, m.betrifft), h("div", { class: "d" }, m.schritte)))) : null);
  } else if (job.ai_error) {
    aiCard = h("div", { class: "alert warn" }, h("div", {}, h("b", {}, "KI-Auswertung fehlgeschlagen"), job.ai_error));
  }
  const c = r.counts;
  put(box, 
    h("div", { class: "card" }, h("div", { class: "card-body score" },
      h("div", { class: "score-ring " + cls }, r.score),
      h("div", {}, h("h2", {}, "Sicherheits-Score"),
        h("p", { class: "muted small" }, `${r.hosts.length} Hosts geprüft in ${r.duration}s · ${fmtTime(job.started)}`),
        h("div", { class: "pill-row" }, ["critical", "high", "medium", "low", "ok"].filter((s) => c[s]).map((s) => h("span", { class: "badge sev-" + s }, `${c[s]} × ${SEV_LABEL[s]}`)))))),
    aiCard,
    h("div", { class: "card" },
      h("div", { class: "card-head" }, h("h2", {}, "Befunde"), h("div", { class: "right" }, filterSel)),
      h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Schwere"), h("th", {}, "Host"), h("th", {}, "Befund"), h("th", {}, "Prüfung"))), tbody))));
}

// ------------------------------------------------------------------ usage (NPM)
const USAGE_ORDER = ["unused", "backend_down", "disabled", "dead_host", "unknown", "used", "external"];
const USAGE_BADGE = { unused: "sev-high", backend_down: "sev-high", disabled: "sev-medium", dead_host: "sev-medium", unknown: "sev-info", used: "sev-ok", external: "sev-info" };
const USAGE_SHORT = { unused: "Ungenutzt", backend_down: "Backend offline", disabled: "Deaktiviert", dead_host: "404-Host", unknown: "Unbekannt", used: "Genutzt", external: "Extern" };

async function viewUsage(page) {
  const d = await api("/api/usage");
  const reload = () => viewUsage(page).catch((e) => toast(e.message, "error"));
  const refreshBtn = h("button", { class: "btn", disabled: !d.configured }, icon("refresh"), "Jetzt prüfen");
  refreshBtn.addEventListener("click", async () => {
    refreshBtn.disabled = true;
    refreshBtn.replaceChildren(icon("refresh"), "Prüfe…");
    try { await api("/api/usage/refresh", { method: "POST" }); toast("Abgleich aktualisiert", "ok"); } catch (e) { toast(e.message, "error"); }
    reload();
  });
  const head = pageHead("Ungenutzte Subdomains",
    "Abgleich deiner Cloudflare-Subdomains mit Nginx Proxy Manager: Was auf dein Netz zeigt, aber keinen (aktiven) Proxy-Host oder kein erreichbares Backend hat, wird gemeldet. Läuft automatisch alle 6 Stunden, neue Funde kommen per Benachrichtigung.",
    refreshBtn);
  if (!d.configured) {
    put(page, head, h("div", { class: "alert info" }, h("div", {}, h("b", {}, "Nginx Proxy Manager nicht verbunden"),
      "In .env ", h("code", {}, "NPM_URL"), " und ", h("code", {}, "NPM_EMAIL"), " setzen, das Passwort in ", h("code", {}, "secrets/npm_password"),
      " ablegen und neu starten. Am besten einen eigenen NPM-Benutzer mit Rechten „View only“ anlegen.")));
    return;
  }
  const rep = d.report;
  const ignored = new Set(d.ignored);
  let filter = "problems";
  const tbody = h("tbody");
  const chips = h("div", { class: "pill-row" });

  function draw() {
    const rows = rep.hosts.filter((x) => filter === "all" ? true : filter === "problems"
      ? ["unused", "backend_down", "disabled", "dead_host"].includes(x.status) && !ignored.has(x.name)
      : filter === "ignored" ? ignored.has(x.name) : x.status === filter)
      .sort((a, b) => USAGE_ORDER.indexOf(a.status) - USAGE_ORDER.indexOf(b.status) || a.name.localeCompare(b.name));
    tbody.replaceChildren(...(rows.length ? rows.map((x) => {
      const isIgn = ignored.has(x.name);
      return h("tr", { class: isIgn ? "muted" : "" },
        h("td", { class: "name" }, x.name, x.ddns ? [" ", h("span", { class: "badge ddns" }, "DDNS")] : null),
        h("td", {}, h("span", { class: "badge " + USAGE_BADGE[x.status], title: d.labels[x.status] || "" }, USAGE_SHORT[x.status] || x.status)),
        h("td", { class: "content small", title: x.records.map((r) => `${r.type} ${r.content}`).join(", ") },
          x.records.map((r) => `${r.type} ${r.content}`).join(", "), " ", cloud(x.records.every((r) => r.proxied))),
        h("td", { class: "small" }, x.npm.length ? x.npm.map((n) => h("div", {},
          h("span", { class: "badge type" }, { proxy: "Proxy", redirect: "Redirect", dead: "404" }[n.kind]), " ", n.target,
          !n.enabled ? [" ", h("span", { class: "badge sev-medium" }, "aus")] : null,
          n.alive === false ? [" ", h("span", { class: "badge sev-high" }, "offline")] : null,
          n.ssl ? [" ", h("span", { class: "badge sev-ok" }, "SSL")] : null,
          n.access_list ? [" ", h("span", { class: "badge sev-low" }, "Access-List")] : null))
          : h("span", { class: "muted" }, "kein NPM-Host")),
        h("td", { class: "actions" },
          h("button", { class: "btn sm link", onclick: () => { state.scanHosts.add(x.name); toast(`${x.name} zum Sicherheitscheck hinzugefügt`, "ok"); } }, "Prüfen"),
          h("button", { class: "btn sm", onclick: async () => {
            try { await api("/api/usage/ignore", { method: "PUT", body: { name: x.name, ignored: !isIgn } }); isIgn ? ignored.delete(x.name) : ignored.add(x.name); draw(); drawChips(); }
            catch (e) { toast(e.message, "error"); }
          } }, isIgn ? "Nicht mehr ignorieren" : "Ignorieren"),
          state.session.allow_dns_delete ? [" ", h("button", { class: "btn sm danger", title: "DNS-Record löschen", onclick: () => {
            const r = x.records[0];
            confirmDeleteRecord({ id: r.zone_id }, { ...r, name: x.name, in_ddns: x.ddns }, () => api("/api/usage/refresh", { method: "POST" }).then(reload, reload));
          } }, icon("trash"))] : null));
    }) : [h("tr", {}, h("td", { colspan: "5", class: "empty" }, filter === "problems" ? "Keine ungenutzten Subdomains 🎉" : "Keine Einträge."))]));
  }
  function drawChips() {
    const problems = rep.hosts.filter((x) => ["unused", "backend_down", "disabled", "dead_host"].includes(x.status) && !ignored.has(x.name)).length;
    const opts = [["problems", `Probleme (${problems})`], ...USAGE_ORDER.filter((k) => rep.counts[k]).map((k) => [k, `${USAGE_SHORT[k]} (${rep.counts[k]})`]),
      ["ignored", `Ignoriert (${ignored.size})`], ["all", `Alle (${rep.hosts.length})`]];
    chips.replaceChildren(...opts.map(([k, label]) => h("button", { class: "chip-btn" + (filter === k ? " active" : ""), onclick: () => { filter = k; draw(); drawChips(); } }, label)));
  }
  drawChips(); draw();

  put(page, head,
    rep.npm_error ? h("div", { class: "alert error" }, h("div", {}, h("b", {}, "NPM-Fehler"), rep.npm_error)) : null,
    h("div", { class: "card" },
      h("div", { class: "card-head" }, h("h2", {}, "Subdomains"), h("span", { class: "sub" }, `${rep.npm_hosts} NPM-Hosts · Stand ${fmtTime(rep.generated)}`)),
      h("div", { class: "card-body tight" }, chips),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Hostname"), h("th", {}, "Status"), h("th", {}, "DNS"), h("th", {}, "Nginx Proxy Manager"), h("th", {}))), tbody))),
    rep.npm_orphans.length ? h("div", { class: "card" },
      h("div", { class: "card-head" }, h("h2", {}, "NPM-Hosts ohne DNS-Eintrag"), h("span", { class: "sub" }, "In NPM konfiguriert, aber bei Cloudflare gibt es keinen Record – evtl. Altlast")),
      h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Domain"), h("th", {}, "Typ"), h("th", {}, "Ziel"))),
        h("tbody", {}, rep.npm_orphans.map((o) => h("tr", {}, h("td", { class: "name" }, o.domain, !o.enabled ? [" ", h("span", { class: "badge sev-medium" }, "aus")] : null),
          h("td", {}, { proxy: "Proxy", redirect: "Redirect", dead: "404" }[o.kind]), h("td", { class: "content" }, o.target))))))) : null);
}

// ------------------------------------------------------------------ scheduled scan
async function viewSchedule(page) {
  const [d, modelsRes] = await Promise.all([api("/api/schedule"), api("/api/ollama/models").catch(() => ({ models: [], default: "" }))]);
  const s = d.settings;
  const reload = () => viewSchedule(page).catch((e) => toast(e.message, "error"));
  async function save(patch) {
    try { await api("/api/schedule/settings", { method: "PUT", body: { ...s, ...patch } }); toast("Gespeichert", "ok"); } catch (e) { toast(e.message, "error"); }
    reload();
  }
  const sel = (value, options, key, fmt) => h("select", { onchange: (e) => save({ [key]: Number(e.target.value) }) },
    options.map((o) => h("option", { value: o, selected: o === value }, fmt(o))));
  const hours = [...Array(25).keys()];
  const usable = (modelsRes.models || []).filter((m) => m.usable);
  const modelSel = h("select", { disabled: !s.ai, onchange: (e) => save({ model: e.target.value }) },
    h("option", { value: "", selected: !s.model }, `Standard (${modelsRes.default || "–"})`),
    usable.map((m) => h("option", { value: m.name, selected: m.name === s.model }, `${m.name} · ${m.size_gb} GB`)));

  const p = d.plan || { total: 0, tested: 0, batch: [], runs_left: 0 };
  const pct = p.total ? Math.round((100 * p.tested) / p.total) : 0;
  const bar = h("div", { class: "progress" }, h("div"));
  bar.firstChild.style.width = pct + "%";
  const runBtn = h("button", { class: "btn", disabled: d.running }, icon("refresh"), d.running ? "Läuft…" : "Nächsten Block jetzt prüfen");
  runBtn.addEventListener("click", async () => {
    try { await api("/api/schedule/run", { method: "POST" }); toast("Block gestartet", "ok"); } catch (e) { toast(e.message, "error"); }
    setTimeout(reload, 800);
  });
  if (d.running) state.pollTimer = setTimeout(reload, 3000);

  const settingsCard = h("div", { class: "card" },
    h("div", { class: "card-head" }, h("h2", {}, "Automatischer Sicherheitscheck"),
      h("span", { class: "badge " + (s.enabled ? "sev-ok" : "sev-medium") }, s.enabled ? "Aktiv" : "Aus"),
      h("div", { class: "right" }, toggle(s.enabled, (v) => save({ enabled: v }), s.enabled ? "Ein" : "Aus"), runBtn)),
    h("div", { class: "card-body settings-grid" },
      h("label", {}, h("span", {}, "Alle Hosts prüfen innerhalb von"), sel(s.period_days, [1, 2, 3, 7, 14, 30], "period_days", (v) => v === 1 ? "1 Tag" : `${v} Tagen`)),
      h("label", {}, h("span", {}, "Ein Block alle"), sel(s.interval_hours, [1, 2, 3, 4, 6, 8, 12, 24], "interval_hours", (v) => `${v} h`)),
      h("label", {}, h("span", {}, `Zeitfenster (${d.timezone})`), h("div", { class: "toolbar" },
        sel(s.window_start, hours.slice(0, 24), "window_start", (v) => `${String(v).padStart(2, "0")}:00`), "–",
        sel(s.window_end, hours.slice(1), "window_end", (v) => `${String(v).padStart(2, "0")}:00`))),
      h("label", {}, h("span", {}, "KI-Zusammenfassung am Ende"), h("div", { class: "toolbar" }, toggle(s.ai, (v) => save({ ai: v })), modelSel)),
      h("label", {}, h("span", {}, "Benachrichtigen"), toggle(s.notify, (v) => save({ notify: v }), "neue hohe Befunde + Abschluss"))),
    h("div", { class: "card-foot" },
      h("div", { class: "cycle" },
        h("div", { class: "toolbar" }, h("b", {}, `${p.tested} von ${p.total} Hosts geprüft`),
          h("span", { class: "muted small" }, d.cycle.completed ? `· Durchgang fertig am ${fmtTime(d.cycle.completed)}, nächster startet ${fmtTime(p.cycle_ends)}`
            : d.cycle.started ? `· Durchgang endet ${fmtTime(p.cycle_ends)} · nächster Block: ${p.batch.length} Host(s), noch ca. ${p.runs_left} Läufe` : "· noch nicht gestartet"),
          h("span", { class: "spacer" }),
          h("button", { class: "btn sm link", onclick: async () => { await api("/api/schedule/reset", { method: "POST" }); toast("Durchgang neu gestartet", "ok"); reload(); } }, "Durchgang neu starten")),
        bar,
        h("div", { class: "small muted" },
          d.running && d.progress ? `Prüfe gerade: ${d.progress.hosts.join(", ")} (${d.progress.done}/${d.progress.total})`
            : [`Letzter Block: ${d.last_run ? fmtTime(d.last_run) : "–"}`, d.last_batch.length ? ` (${d.last_batch.join(", ")})` : "",
              s.enabled && d.next_run ? ` · Nächster: ${fmtTime(Math.max(d.next_run, Date.now() / 1000))}` : ""].join("")),
        d.last_error ? h("div", { class: "alert error small" }, d.last_error) : null)));

  let summaryCard = null;
  if (d.summary) {
    const sm = d.summary, a = sm.ai;
    summaryCard = h("div", { class: "card" },
      h("div", { class: "card-head" }, h("h2", {}, "Letzter vollständiger Durchgang"), h("span", { class: "sub" }, `${fmtTime(sm.ts)} · ${sm.hosts} Hosts · Score ${sm.score}/100`),
        a ? h("span", { class: "badge sev-" + ({ niedrig: "low", mittel: "medium", hoch: "high", kritisch: "critical" }[a.risiko] || "info") }, "Risiko: " + a.risiko) : null),
      a ? [h("div", { class: "card-body" }, h("p", {}, a.zusammenfassung)),
        a.massnahmen.length ? h("ol", { class: "steps" }, a.massnahmen.map((m) => h("li", {}, h("div", { class: "t" }, m.titel), h("div", { class: "b" }, m.betrifft), h("div", { class: "d" }, m.schritte)))) : null]
        : h("div", { class: "card-body" }, sm.ai_error ? h("div", { class: "alert warn" }, sm.ai_error) : h("span", { class: "muted" }, "Ohne KI-Zusammenfassung.")));
  }

  const rows = d.hosts.map((x) => {
    const c = x.counts || {};
    return h("tr", { class: x.excluded ? "muted" : "" },
      h("td", { class: "name" }, x.name, x.excluded ? [" ", h("span", { class: "badge sev-info" }, "ausgeschlossen")] : null),
      h("td", { class: "nowrap small" }, x.ts ? fmtAgo(x.ts) : h("span", { class: "muted" }, "noch nie"), x.tested_this_cycle ? [" ", h("span", { class: "badge sev-ok" }, "✓")] : null),
      h("td", {}, x.score === null || x.score === undefined ? "–" : h("span", { class: "badge " + (x.score >= 80 ? "sev-ok" : x.score >= 50 ? "sev-medium" : "sev-high") }, x.score)),
      h("td", {}, h("div", { class: "pill-row" }, ["critical", "high", "medium", "low"].filter((k) => c[k]).map((k) => h("span", { class: "badge sev-" + k }, `${c[k]} ${SEV_LABEL[k]}`)))),
      h("td", { class: "actions" },
        x.ts ? h("button", { class: "btn sm link", onclick: () => showHostFindings(x.name) }, "Details") : null,
        h("button", { class: "btn sm", onclick: async () => {
          try { await api("/api/schedule/exclude", { method: "PUT", body: { name: x.name, excluded: !x.excluded } }); reload(); } catch (e) { toast(e.message, "error"); }
        } }, x.excluded ? "Einschließen" : "Ausschließen")));
  });
  const zoneRows = Object.entries(d.zones).flatMap(([z, v]) => v.findings.filter((f) => !["ok", "info"].includes(f.severity)).map((f) =>
    h("tr", {}, h("td", {}, sevBadge(f.severity)), h("td", { class: "name" }, z), h("td", {}, h("b", {}, f.title), f.detail ? h("div", { class: "muted small" }, f.detail) : null))));

  put(page,
    pageHead("Wochen-Scan", "Prüft automatisch in kleinen Blöcken, bis alle Subdomains im gewählten Zeitraum getestet sind – schont Netz und GPU. Danach beginnt der nächste Durchgang. Manuelle Scans zählen mit."),
    settingsCard, summaryCard,
    zoneRows.length ? h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Zonen-Befunde"), h("span", { class: "sub" }, "SSL-Modus, E-Mail-Schutz, DNSSEC …")),
      h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {}, zoneRows)))) : null,
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Ergebnisse je Host"), h("span", { class: "sub" }, `${d.hosts.length} Hosts`)),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Hostname"), h("th", {}, "Zuletzt geprüft"), h("th", {}, "Score"), h("th", {}, "Befunde"), h("th", {}))),
        h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colspan: "5", class: "empty" }, "Keine Hosts.")))))));
}

async function showHostFindings(name) {
  try {
    const r = await api(`/api/schedule/host?name=${encodeURIComponent(name)}`);
    const list = r.findings.filter((f) => f.severity !== "info");
    modal({ title: `${name} · Score ${r.score}`, wide: true, cancel: false, confirmText: "Schließen", onConfirm: () => true,
      body: [h("p", { class: "muted small" }, `Geprüft ${fmtTime(r.ts)}`),
        h("div", { class: "table-wrap import-table" }, h("table", {}, h("tbody", {}, list.length ? list.map((f) => h("tr", {}, h("td", {}, sevBadge(f.severity)),
          h("td", {}, h("b", {}, f.title), f.detail ? h("div", { class: "muted small" }, f.detail) : null), h("td", { class: "muted small" }, f.check)))
          : h("tr", {}, h("td", { class: "empty" }, "Keine Befunde.")))))] });
  } catch (e) { toast(e.message, "error"); }
}

// ------------------------------------------------------------------ audit
async function viewAudit(page) {
  const [entries, sess] = await Promise.all([api("/api/audit"), api("/api/sessions")]);
  const sessCard = h("div", { class: "card" },
    h("div", { class: "card-head" }, h("h2", {}, "Aktive Sitzungen"), h("span", { class: "sub" }, `${sess.length} angemeldet`),
      sess.length > 1 ? h("div", { class: "right" }, h("button", { class: "btn sm danger", onclick: async () => {
        try { const r = await api("/api/sessions/revoke-others", { method: "POST" }); toast(`${r.revoked} Sitzung(en) abgemeldet`, "ok"); renderView(); }
        catch (e) { toast(e.message, "error"); }
      } }, "Alle anderen abmelden")) : null),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Benutzer"), h("th", {}, "Anmeldung"), h("th", {}, "IP"), h("th", {}, "Gerät"), h("th", {}, "Seit"), h("th", {}, "Zuletzt aktiv"))),
      h("tbody", {}, sess.map((x) => h("tr", {},
        h("td", { class: "name" }, x.user, x.current ? [" ", h("span", { class: "badge sev-ok" }, "diese")] : null),
        h("td", {}, x.method === "sso" ? "SSO" : "Passwort"), h("td", { class: "mono small" }, x.ip),
        h("td", { class: "content small", title: x.agent }, x.agent || "–"),
        h("td", { class: "nowrap small" }, fmtTime(x.created)), h("td", { class: "nowrap small" }, fmtAgo(x.last_seen))))))));
  const fmt = (e) => {
    const { ts, event, ip, ...rest } = e;
    return Object.entries(rest).map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join("  ");
  };
  put(page, pageHead("Audit-Log", "Anmeldungen und alle Änderungen. Gespeichert in /data/audit.log.",
    h("button", { class: "btn", onclick: () => renderView() }, icon("refresh"), "Aktualisieren")),
    sessCard,
    h("div", { class: "card" }, h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Zeit"), h("th", {}, "Ereignis"), h("th", {}, "IP"), h("th", {}, "Details"))),
      h("tbody", {}, entries.length ? entries.map((e) => h("tr", {},
        h("td", { class: "nowrap small" }, e.ts),
        h("td", {}, h("span", { class: "badge " + (/failed|blocked/.test(e.event) ? "sev-high" : /deleted/.test(e.event) ? "sev-medium" : "sev-info") }, e.event)),
        h("td", { class: "mono small" }, e.ip),
        h("td", { class: "content", title: fmt(e) }, fmt(e))))
        : h("tr", {}, h("td", { colspan: "4", class: "empty" }, "Noch keine Einträge.")))))));
}

// ------------------------------------------------------------------ boot
async function boot() {
  const info = await api("/api/session");
  state.sessionInfo = info;
  if (!info.authenticated) { renderLogin(); return; }
  state.session = info;
  const hash = location.hash.slice(1);
  if (NAV.some(([id]) => id === hash)) state.view = hash;
  renderShell();
}

document.addEventListener("DOMContentLoaded", () => boot().catch((e) => {
  document.getElementById("app").replaceChildren(h("div", { class: "boot" }, "Fehler: " + e.message));
}));
