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

function modal({ title, body, confirmText = "OK", danger = false, onConfirm }) {
  const close = () => ov.remove();
  const btn = h("button", { class: "btn " + (danger ? "danger solid" : "primary") }, confirmText);
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try { if ((await onConfirm()) !== false) close(); } catch (e) { toast(e.message, "error"); } finally { btn.disabled = false; }
  });
  const ov = h("div", { class: "overlay", onclick: (e) => { if (e.target === ov) close(); } },
    h("div", { class: "modal", role: "dialog", "aria-modal": "true" },
      h("div", { class: "card-head" }, h("h2", {}, title)),
      h("div", { class: "card-body" }, body),
      h("div", { class: "card-foot" }, h("span", { class: "spacer" }), h("button", { class: "btn", onclick: close }, "Abbrechen"), btn)));
  document.body.append(ov);
  const first = ov.querySelector("input");
  (first || btn).focus();
}

function errorBox(e) { return h("div", { class: "alert error" }, h("div", {}, h("b", {}, "Fehler"), e.message || String(e))); }
function loading() { return h("div", { class: "card" }, h("div", { class: "card-body" }, h("div", { class: "progress indeterminate" }, h("div")))); }

// ------------------------------------------------------------------ login
function renderLogin(notice) {
  stopPoll();
  const s = state.sessionInfo || {};
  const err = h("div", { class: "alert error hidden" });
  const user = h("input", { type: "text", name: "username", autocomplete: "username", required: true, maxlength: "64" });
  const pass = h("input", { type: "password", name: "password", autocomplete: "current-password", required: true, maxlength: "256" });
  const otp = h("input", { type: "text", name: "otp", autocomplete: "one-time-code", inputmode: "numeric", pattern: "[0-9 ]*", maxlength: "10" });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Anmelden");
  const form = h("form", { class: "card-body", onsubmit: async (e) => {
    e.preventDefault();
    btn.disabled = true;
    err.classList.add("hidden");
    try {
      await api("/api/login", { method: "POST", body: { user: user.value, password: pass.value, otp: otp.value } });
      pass.value = "";
      await boot();
    } catch (ex) {
      err.replaceChildren(ex.message);
      err.classList.remove("hidden");
      pass.value = ""; otp.value = "";
    } finally { btn.disabled = false; }
  } },
    notice ? h("div", { class: "alert info" }, notice) : null,
    s.login_enabled === false ? h("div", { class: "alert warn" }, h("div", {}, h("b", {}, "Login deaktiviert"), "Es ist kein ADMIN_PASSWORD_HASH konfiguriert. Siehe README.")) : null,
    err,
    h("label", { class: "field" }, h("span", {}, "Benutzername"), user),
    h("label", { class: "field" }, h("span", {}, "Passwort"), pass),
    s.totp ? h("label", { class: "field" }, h("span", {}, "2FA-Code"), otp) : null,
    btn);
  document.getElementById("app").replaceChildren(
    h("div", { class: "login-wrap" }, h("div", { class: "login" },
      h("div", { class: "brand" }, logo(), "DomainManager"),
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Anmelden")), form),
      h("div", { class: "foot" }, "Zugriff wird protokolliert."))));
  user.focus();
}

// ------------------------------------------------------------------ shell
const NAV = [
  ["overview", "Übersicht", "home"],
  ["dns", "DNS-Einträge", "dns"],
  ["ddns", "DDNS-Domains", "ddns"],
  ["scan", "Sicherheitscheck", "shield"],
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
  const views = { overview: viewOverview, dns: viewDns, ddns: viewDdns, scan: viewScan, audit: viewAudit };
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
  const cfS = st.cloudflare, ol = st.ollama, dd = st.ddns, ap = st.applier;
  const cards = h("div", { class: "grid" },
    stat("Cloudflare API", cfS.ok ? "ok" : "bad", cfS.ok ? "Verbunden" : "Fehler",
      cfS.ok ? (cfS.type === "token" ? "API-Token aktiv" : "Global API Key – besser einen eingeschränkten Token verwenden!") : cfS.error),
    stat("Ollama", ol.ok ? (ol.default_available ? "ok" : "warn") : "bad", ol.ok ? `${ol.models} Modelle` : "Nicht erreichbar",
      ol.ok ? (ol.default_available ? `Standard: ${ol.default_model}` : `Standardmodell ${ol.default_model} fehlt`) : `${ol.url} – ${ol.error}`),
    stat("DDNS-Konfiguration", dd.exists && dd.writable ? "ok" : "bad", dd.exists ? (dd.writable ? "Beschreibbar" : "Nur lesbar") : "Datei fehlt", dd.file),
    stat("Applier", !ap.enabled ? "warn" : ap.alive ? "ok" : "bad", !ap.enabled ? "Deaktiviert" : ap.alive ? "Bereit" : "Keine Rückmeldung",
      ap.last_result ? `Letzter Lauf: ${ap.last_result.ok ? "erfolgreich" : "fehlgeschlagen"} (${fmtTime(ap.last_result.finished)})` : "Erstellt den DDNS-Container nach Änderungen neu"));

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
      h("td", {}, r.proxiable ? cloud(r.proxied) : h("span", { class: "muted small" }, "–")),
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
      r.in_ddns ? h("div", { class: "alert warn" }, "Dieser Name steht noch in der DDNS-Liste – cloudflare-ddns würde ihn wieder anlegen. Zuerst unter „DDNS-Domains“ entfernen.") : null,
      h("label", { class: "field" }, h("span", {}, "Zur Bestätigung den Namen eintippen"), input)],
    onConfirm: async () => {
      await api(`/api/zones/${zone.id}/records/${r.id}`, { method: "DELETE", body: { confirm: input.value } });
      toast(`${r.name} gelöscht`, "ok");
      after();
    },
  });
}

// ------------------------------------------------------------------ ddns
async function viewDdns(page) {
  const data = await api("/api/ddns");
  const pending = {};
  for (const [k, list] of Object.entries(data.keys)) pending[k] = { orig: list, removed: new Set(), added: [] };
  const saveBtn = h("button", { class: "btn primary", disabled: true }, "Änderungen speichern");
  const applyBox = h("div");

  const dirty = () => Object.values(pending).some((p) => p.removed.size || p.added.length);
  const refreshSave = () => { saveBtn.disabled = !dirty(); };

  function keyCard(key) {
    const p = pending[key];
    const tbody = h("tbody");
    const draw = () => {
      const rows = [];
      for (const d of p.orig) {
        const rem = p.removed.has(d.name);
        const recs = d.records;
        rows.push(h("tr", { class: rem ? "muted" : "" },
          h("td", { class: "name" }, rem ? h("s", {}, d.name) : d.name),
          h("td", { class: "content" }, recs.length ? recs.map((r) => `${r.type} ${r.content}`).join(", ") : h("span", { class: "muted" }, "kein A/AAAA-Record")),
          h("td", {}, recs.length ? cloud(recs.every((r) => r.proxied)) : "–"),
          h("td", { class: "actions" }, rem
            ? h("button", { class: "btn sm", onclick: () => { p.removed.delete(d.name); draw(); refreshSave(); } }, "Rückgängig")
            : h("button", { class: "btn sm danger", onclick: () => { p.removed.add(d.name); draw(); refreshSave(); } }, icon("trash"), "Entfernen"))));
      }
      for (const name of p.added) {
        rows.push(h("tr", {}, h("td", { class: "name" }, name, " ", h("span", { class: "badge sev-ok" }, "neu")), h("td", { class: "muted" }, "wird nach dem Anwenden angelegt"), h("td", {}, "–"),
          h("td", { class: "actions" }, h("button", { class: "btn sm", onclick: () => { p.added = p.added.filter((x) => x !== name); draw(); refreshSave(); } }, "Verwerfen"))));
      }
      tbody.replaceChildren(...(rows.length ? rows : [h("tr", {}, h("td", { colspan: "4", class: "empty" }, `${key} ist leer.`))]));
    };
    draw();
    const add = h("input", { type: "text", placeholder: "sub.beispiel.de", autocomplete: "off" });
    const doAdd = () => {
      const v = add.value.trim().toLowerCase().replace(/\.$/, "");
      if (!/^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/.test(v)) { toast("Ungültiger Hostname", "error"); return; }
      if (p.orig.some((d) => d.name === v) || p.added.includes(v)) { toast("Bereits vorhanden", "error"); return; }
      p.added.push(v); add.value = ""; draw(); refreshSave();
    };
    add.addEventListener("keydown", (e) => { if (e.key === "Enter") doAdd(); });
    return h("div", { class: "card" },
      h("div", { class: "card-head" }, h("h2", {}, h("code", {}, key)), h("span", { class: "sub" }, `${p.orig.length} Hosts`),
        h("div", { class: "right" }, add, h("button", { class: "btn sm", onclick: doAdd }, icon("plus"), "Hinzufügen"))),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Hostname"), h("th", {}, "Aktueller Record"), h("th", {}, "Proxy"), h("th", {}))), tbody)));
  }

  saveBtn.addEventListener("click", () => {
    const removed = Object.values(pending).flatMap((p) => [...p.removed]);
    const added = Object.values(pending).flatMap((p) => p.added);
    const removedWithRecords = Object.values(pending).flatMap((p) => p.orig.filter((d) => p.removed.has(d.name) && d.records.length));
    const delBox = h("input", { type: "checkbox" });
    modal({
      title: "DDNS-Liste ändern", confirmText: "Speichern",
      body: [
        removed.length ? h("p", {}, h("b", {}, "Entfernen: "), removed.join(", ")) : null,
        added.length ? h("p", {}, h("b", {}, "Hinzufügen: "), added.join(", ")) : null,
        h("p", { class: "muted small" }, "Vorher wird automatisch ein Backup der Datei angelegt. Danach den DDNS-Container über „Jetzt anwenden“ neu erstellen lassen."),
        removedWithRecords.length && state.session.allow_dns_delete
          ? h("label", { class: "check" }, delBox, `Auch die ${removedWithRecords.length} zugehörigen DNS-Records bei Cloudflare löschen`)
          : removedWithRecords.length ? h("div", { class: "alert info small" }, "Hinweis: cloudflare-ddns löscht die DNS-Records nicht. Sie bleiben bei Cloudflare bestehen (mit der zuletzt gesetzten IP).") : null,
      ],
      onConfirm: async () => {
        const body = { domains: {} };
        for (const [k, p] of Object.entries(pending))
          body.domains[k] = p.orig.map((d) => d.name).filter((n) => !p.removed.has(n)).concat(p.added);
        await api("/api/ddns", { method: "PUT", body });
        toast("DDNS-Liste gespeichert", "ok");
        if (delBox.checked) {
          for (const d of removedWithRecords)
            for (const r of d.records) {
              try { await api(`/api/zones/${r.zone_id}/records/${r.id}`, { method: "DELETE", body: { confirm: d.name } }); toast(`${r.type} ${d.name} gelöscht`, "ok"); }
              catch (e) { toast(`${d.name}: ${e.message}`, "error"); }
            }
        }
        await viewDdns(page);
        showApply(true);
      },
    });
  });

  function showApply(highlight) {
    const ap = data.applier;
    const st = h("div", { class: "small muted" });
    const prog = h("div", { class: "progress indeterminate hidden" }, h("div"));
    const btn = h("button", { class: "btn primary", disabled: !ap.enabled }, icon("ddns"), "Jetzt anwenden");
    const lastRes = (r) => r ? h("span", {}, `Letzter Lauf ${fmtTime(r.finished)}: `, h("span", { class: "badge " + (r.ok ? "sev-ok" : "sev-high") }, r.ok ? "erfolgreich" : `Fehler (Exit ${r.exit_code})`)) : "Noch nicht ausgeführt.";
    st.append(lastRes(ap.last_result));
    const out = h("pre", { class: "small mono hidden" });
    btn.addEventListener("click", async () => {
      btn.disabled = true; prog.classList.remove("hidden");
      try {
        const { nonce } = await api("/api/ddns/apply", { method: "POST" });
        const started = Date.now();
        const poll = async () => {
          const s = await api("/api/ddns/apply");
          if (s.last_result && s.last_result.nonce === nonce) {
            prog.classList.add("hidden"); btn.disabled = false;
            st.replaceChildren(lastRes(s.last_result));
            out.textContent = s.last_result.output || ""; out.classList.toggle("hidden", !out.textContent);
            toast(s.last_result.ok ? "DDNS-Container neu erstellt" : "Anwenden fehlgeschlagen", s.last_result.ok ? "ok" : "error");
          } else if (Date.now() - started > 120000) {
            prog.classList.add("hidden"); btn.disabled = false;
            toast("Applier antwortet nicht. Läuft der Container 'applier'?", "error");
          } else state.pollTimer = setTimeout(() => poll().catch((e) => toast(e.message, "error")), 1500);
        };
        poll();
      } catch (e) { toast(e.message, "error"); btn.disabled = false; prog.classList.add("hidden"); }
    });
    applyBox.replaceChildren(h("div", { class: "card" + (highlight ? " highlight" : "") },
      h("div", { class: "card-head" }, h("h2", {}, "Änderungen anwenden"),
        h("span", { class: "sub" }, "cloudflare-ddns liest die Domains nur beim Start – der Container wird dafür neu erstellt."),
        h("div", { class: "right" }, h("span", { class: "dot " + (!ap.enabled ? "warn" : ap.alive ? "ok" : "bad") }), h("span", { class: "small" }, !ap.enabled ? "Applier deaktiviert" : ap.alive ? "Applier bereit" : "Applier offline"), btn)),
      h("div", { class: "card-body" }, prog, st, out,
        !ap.enabled ? h("p", { class: "small" }, "Manuell im CloudflareDNS-Verzeichnis: ", h("code", {}, "docker compose up -d cloudflare-ddns")) : null)));
  }

  const st = data.status;
  put(page, 
    pageHead("DDNS-Domains", "Hosts, deren IP der Container favonia/cloudflare-ddns automatisch aktualisiert. Entfernte Hosts werden danach nicht mehr aktualisiert.", saveBtn),
    !st.exists ? h("div", { class: "alert warn" }, h("div", {}, h("b", {}, "DDNS-Datei nicht gefunden"), `${st.file} existiert nicht. Siehe README → „DDNS-Container umstellen“.`)) : null,
    st.exists && !st.writable ? h("div", { class: "alert error" }, `${st.file} ist nicht beschreibbar.`) : null,
    data.cf_error ? h("div", { class: "alert warn" }, data.cf_error) : null,
    Object.keys(pending).map(keyCard),
    applyBox);
  showApply(false);
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

// ------------------------------------------------------------------ audit
async function viewAudit(page) {
  const entries = await api("/api/audit");
  const fmt = (e) => {
    const { ts, event, ip, ...rest } = e;
    return Object.entries(rest).map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join("  ");
  };
  put(page, pageHead("Audit-Log", "Anmeldungen und alle Änderungen. Gespeichert in /data/audit.log.",
    h("button", { class: "btn", onclick: () => renderView() }, icon("refresh"), "Aktualisieren")),
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
