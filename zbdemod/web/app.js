"use strict";
/* Zigbee network map: polls /api/state and draws a force-directed graph. */

const $ = (id) => document.getElementById(id);
const SVGNS = "http://www.w3.org/2000/svg";
const ROLE_RANK = { coordinator: 3, router: 2, end_device: 1, unknown: 0 };
const ROLE_NAME = { coordinator: "Coordinator", router: "Router", end_device: "End device", unknown: "Role unknown" };
const RADIUS = { coordinator: 11, router: 8, end_device: 5, unknown: 6.5 };
const LINK_LEN = { radio: 95, neighbor: 105, parent: 45, route: 120 };
const SLOTS = 8;

const store = {
  get(key, fallback) {
    try {
      const v = localStorage.getItem("zbmap." + key);
      return v === null ? fallback : JSON.parse(v);
    } catch { return fallback; }
  },
  set(key, value) {
    try { localStorage.setItem("zbmap." + key, JSON.stringify(value)); } catch { /* private mode */ }
  },
};

const prefs = Object.assign(
  { colorBy: "network", linkColor: "cost", labelBy: "name", staleAfter: 300, showRoutes: true, showFlows: false,
    hideStale: false, logOpen: true, dwell: 5 },
  store.get("prefs", {}),
);

const S = {
  snap: null, version: "", clockOffset: 0, connected: null,
  nodes: new Map(), links: [], flows: [], centers: new Map(), netSlot: new Map(),
  selected: null, selectedNet: null, hidden: new Set(store.get("hidden", [])),
  view: { x: 0, y: 0, k: 1 }, userView: false, fitting: true,
  alpha: 1, drag: null, raf: 0, savedPos: store.get("pos", {}), lastSave: 0,
  rssiRange: [0, 0],
};

// ------------------------------------------------------------------ utils
function svg(tag, attrs = {}) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function nowS() {
  if (!S.snap) return Date.now() / 1000;
  return S.snap.live ? Date.now() / 1000 + S.clockOffset : S.snap.now;
}
function ago(t) {
  if (t == null) return "—";
  const s = Math.max(0, nowS() - t);
  const tail = S.snap && !S.snap.live ? " before the end" : " ago";
  if (s < 1) return S.snap && !S.snap.live ? "at the end" : "just now";
  if (s < 60) return `${Math.floor(s)} s${tail}`;
  if (s < 3600) return `${Math.floor(s / 60)} min${tail}`;
  return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min${tail}`;
}
function clock(t) {
  if (t == null) return "—";
  const d = new Date(t * 1000);
  return d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}
const fmt = (v, digits = 1, unit = "") => (v == null ? "—" : `${v.toFixed(digits).replace("-", "−")}${unit}`);
const panHex = (pan) => "0x" + pan.toString(16).padStart(4, "0");
const mhz = (ch) => 2405 + 5 * (ch - 11);

function nodeTitle(d) { return d.name || d.model || d.short || d.ieee; }
const clip = (s, n = 22) => (s && s.length > n ? s.slice(0, n - 1) + "…" : s);
const shortIeee = (ieee) => (ieee ? ieee.slice(0, 5) + "…" + ieee.slice(-5) : ieee);
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
function labelFor(d) {
  switch (prefs.labelBy) {
    case "short": return d.short || shortIeee(d.ieee);
    case "ieee": return d.ieee || d.short;
    case "vendor": return d.vendor || d.short || shortIeee(d.ieee);
    case "none": return "";
    default: return clip(d.name || d.model) || d.short || shortIeee(d.ieee);
  }
}
function slotVar(pan) {
  const i = S.netSlot.get(pan);
  return i == null || i >= SLOTS ? "var(--other)" : `var(--s${i + 1})`;
}
function signalVar(d) {
  if (!d.heard || d.rssi == null) return "var(--other)";
  const [lo, hi] = S.rssiRange;
  const f = hi > lo ? (d.rssi - lo) / (hi - lo) : 1;
  return `var(--q${1 + Math.min(4, Math.floor(f * 5))})`;
}
// Link cost 1 (best) .. 7 (worst) on the sequential ramp: better = stronger.
function costVar(cost) {
  return `var(--q${cost <= 1 ? 5 : cost === 2 ? 4 : cost === 3 ? 3 : cost <= 5 ? 2 : 1})`;
}
const nodeColor = (d) => (prefs.colorBy === "signal" ? signalVar(d) : slotVar(d.pan));
function isStale(t) { return prefs.staleAfter > 0 && t != null && nowS() - t > prefs.staleAfter; }
function nodeVisible(n) {
  if (S.hidden.has(n.data.pan)) return false;
  if (prefs.hideStale && isStale(n.data.last_seen)) return false;
  return true;
}
function linkVisible(l) {
  if (!l.s || !l.t || !nodeVisible(l.s) || !nodeVisible(l.t)) return false;
  return l.data.kind !== "route" || prefs.showRoutes;
}
function shape(role, r) {
  if (role === "unknown") return `M0,${-r * 1.25}L${r * 1.25},0L0,${r * 1.25}L${-r * 1.25},0Z`;
  return `M${-r},0a${r},${r} 0 1,0 ${2 * r},0a${r},${r} 0 1,0 ${-2 * r},0`;
}

// -------------------------------------------------------------- polling
async function poll() {
  try {
    const r = await fetch(`api/state?v=${S.version}`, { cache: "no-store" });
    if (r.status === 200) {
      const snap = await r.json();
      S.version = String(snap.version);
      apply(snap);
    } else if (r.status === 204) {
      refreshTimes();
    }
    setConnected(r.ok);
  } catch {
    setConnected(false);
  }
  setTimeout(poll, 1000);
}

function setConnected(ok) {
  if (S.connected === ok) return;
  S.connected = ok;
  renderHeader();
}

// ---------------------------------------------------------------- model
function apply(snap) {
  S.snap = snap;
  S.clockOffset = snap.now - Date.now() / 1000;
  for (const net of snap.networks) if (!S.netSlot.has(net.pan)) S.netSlot.set(net.pan, S.netSlot.size);
  layoutCenters(snap.networks);
  const rs = snap.nodes.filter((d) => d.heard && d.rssi != null).map((d) => d.rssi);
  S.rssiRange = rs.length ? [Math.min(...rs), Math.max(...rs)] : [0, 0];

  const adj = new Map();
  for (const l of snap.links) {
    if (!adj.has(l.a)) adj.set(l.a, []);
    if (!adj.has(l.b)) adj.set(l.b, []);
    adj.get(l.a).push(l.b);
    adj.get(l.b).push(l.a);
  }
  let added = 0;
  const seen = new Set();
  for (const d of [...snap.nodes].sort((a, b) => ROLE_RANK[b.role] - ROLE_RANK[a.role])) {
    seen.add(d.id);
    let n = S.nodes.get(d.id);
    if (!n) {
      n = createNode(d, adj);
      S.nodes.set(d.id, n);
      added++;
    } else if (d.last_tx != null && d.last_tx !== n.data.last_tx) {
      pulse(n);
    }
    n.data = d;
  }
  for (const [id, n] of S.nodes) {
    if (!seen.has(id)) {
      n.el.remove();
      S.nodes.delete(id);
      if (S.selected === id) S.selected = null;
    }
  }
  if (S.selectedNet != null && !snap.networks.some((x) => x.pan === S.selectedNet)) S.selectedNet = null;
  const before = S.links.length;
  syncLinks(snap.links);
  syncFlows(snap.flows);
  if (added || S.links.length !== before) reheat(added ? 0.7 : 0.35);
  restyle();
  renderAll();
}

function layoutCenters(nets) {
  // Shelf-pack one circle per network (radius grows with its device count),
  // in discovery order so clusters do not jump around as networks appear.
  const radius = (net) => 50 + 42 * Math.sqrt(Math.max(1, net.nodes));
  const area = nets.reduce((a, net) => a + (2 * radius(net)) ** 2, 0);
  const maxW = Math.max(...nets.map((net) => 2 * radius(net)), Math.sqrt(area) * 1.5);
  const placed = [];
  let x = 0, y = 0, rowH = 0;
  for (const net of nets) {
    const d = 2 * radius(net);
    if (x > 0 && x + d > maxW) { x = 0; y += rowH + 40; rowH = 0; }
    placed.push([net.pan, x + d / 2, y + d / 2]);
    x += d + 40;
    rowH = Math.max(rowH, d);
  }
  const w = Math.max(0, ...nets.map((net, i) => placed[i][1] + radius(net)));
  const h = Math.max(0, ...nets.map((net, i) => placed[i][2] + radius(net)));
  S.centers = new Map(placed.map(([pan, px, py]) => [pan, { x: px - w / 2, y: py - h / 2 }]));
}

function createNode(d, adj) {
  const saved = S.savedPos[d.id];
  let x, y, pinned = false;
  if (saved) {
    [x, y, pinned] = saved;
  } else {
    const nb = (adj.get(d.id) || []).map((id) => S.nodes.get(id)).find(Boolean);
    const c = nb || S.centers.get(d.pan) || { x: 0, y: 0 };
    const a = Math.random() * 2 * Math.PI;
    const r = nb ? 30 + Math.random() * 20 : d.role === "coordinator" ? 0 : 60 + Math.random() * 80;
    x = c.x + Math.cos(a) * r;
    y = c.y + Math.sin(a) * r;
  }
  const n = { id: d.id, x, y, vx: 0, vy: 0, fx: pinned ? x : null, fy: pinned ? y : null, data: d, deg: 0 };
  const g = svg("g", { class: "node", tabindex: "0", role: "button" });
  g.append(
    svg("circle", { class: "pulse", r: "8" }),
    svg("circle", { class: "ring" }),
    svg("path", { class: "body" }),
    svg("circle", { class: "sel" }),
    svg("circle", { class: "pin", r: "2" }),
    svg("text", { class: "label" }),
  );
  g.addEventListener("pointerdown", (e) => startDrag(e, n));
  g.addEventListener("pointerenter", (e) => showTip(e, nodeTip(n.data)));
  g.addEventListener("pointermove", moveTip);
  g.addEventListener("pointerleave", hideTip);
  g.addEventListener("dblclick", (e) => {
    e.stopPropagation();
    n.fx = n.fy = null;
    styleNode(n);
    reheat(0.25);
    savePositions(true);
  });
  g.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      select(n.id);
    }
  });
  $("gNodes").append(g);
  n.el = g;
  return n;
}

function pulse(n) {
  const p = n.el.querySelector(".pulse");
  p.classList.remove("go");
  void p.getBoundingClientRect();
  p.classList.add("go");
  clearTimeout(n.pulseTimer);
  n.pulseTimer = setTimeout(() => p.classList.remove("go"), 1000);
}

function syncLinks(list) {
  const old = new Map(S.links.map((l) => [l.key, l]));
  const next = [];
  for (const d of list) {
    const key = d.a + "|" + d.b;
    let l = old.get(key);
    if (!l) {
      l = { key, el: svg("line", { class: "link" }), hit: svg("line", { class: "hit" }) };
      l.hit.addEventListener("pointerenter", (e) => showTip(e, linkTip(l)));
      l.hit.addEventListener("pointermove", moveTip);
      l.hit.addEventListener("pointerleave", hideTip);
      $("gLinks").append(l.el);
      $("gHits").append(l.hit);
    } else {
      old.delete(key);
      const tot = (x) => x.ab + x.ba + x.relay + x.route + x.acked;
      if (tot(d) !== tot(l.data)) flash(l);
    }
    l.data = d;
    l.s = S.nodes.get(d.a);
    l.t = S.nodes.get(d.b);
    next.push(l);
  }
  for (const l of old.values()) { l.el.remove(); l.hit.remove(); }
  S.links = next;
  for (const n of S.nodes.values()) n.deg = 0;
  for (const l of next) { if (l.s) l.s.deg++; if (l.t) l.t.deg++; }
}

function flash(l) {
  l.el.classList.add("flash");
  setTimeout(() => l.el.classList.remove("flash"), 450);
}

function syncFlows(list) {
  for (const f of S.flows) f.el.remove();
  S.flows = [];
  for (const d of list) {
    const el = svg("path", { class: "flow", "marker-end": "url(#arrow)" });
    $("gFlows").append(el);
    S.flows.push({ data: d, el, s: S.nodes.get(d.src), t: S.nodes.get(d.dst) });
  }
}

// ----------------------------------------------------------- simulation
function reheat(a) {
  S.alpha = Math.max(S.alpha, a);
  kick();
}
function kick() {
  if (!S.raf) S.raf = requestAnimationFrame(frame);
}

function tick() {
  const nodes = [...S.nodes.values()].filter(nodeVisible);
  const a = S.alpha;
  for (let i = 0; i < nodes.length; i++) {
    const p = nodes[i];
    for (let j = i + 1; j < nodes.length; j++) {
      const q = nodes[j];
      let dx = q.x - p.x, dy = q.y - p.y;
      let d2 = dx * dx + dy * dy;
      if (d2 > 640000) continue;
      if (d2 < 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 1; }
      const s = ((p.data.pan === q.data.pan ? 380 : 260) * a) / Math.max(d2, 400);
      p.vx -= dx * s; p.vy -= dy * s;
      q.vx += dx * s; q.vy += dy * s;
    }
  }
  for (const l of S.links) {
    if (!linkVisible(l)) continue;
    const s = l.s, t = l.t;
    const dx = t.x + t.vx - s.x - s.vx, dy = t.y + t.vy - s.y - s.vy;
    const d = Math.sqrt(dx * dx + dy * dy) || 1;
    const len = LINK_LEN[l.data.kind] || 90;
    const strength = 0.7 / Math.max(1, Math.min(s.deg, t.deg));
    const k = ((d - len) / d) * a * strength;
    const bias = s.deg / (s.deg + t.deg || 1);
    t.vx -= dx * k * bias; t.vy -= dy * k * bias;
    s.vx += dx * k * (1 - bias); s.vy += dy * k * (1 - bias);
  }
  for (const p of nodes) {
    const c = S.centers.get(p.data.pan) || { x: 0, y: 0 };
    const g = (p.data.role === "coordinator" ? 0.09 : p.deg ? 0.012 : 0.08) * a;
    p.vx += (c.x - p.x) * g;
    p.vy += (c.y - p.y) * g;
    if (p.fx != null) {
      p.x = p.fx; p.y = p.fy; p.vx = p.vy = 0;
    } else {
      p.vx *= 0.6; p.vy *= 0.6;
      p.x += p.vx; p.y += p.vy;
    }
  }
  S.alpha += (0 - S.alpha) * 0.02;
}

function frame() {
  S.raf = 0;
  const dragging = S.drag && S.drag.node;
  if (S.alpha > 0.004 || dragging) {
    if (dragging) S.alpha = Math.max(S.alpha, 0.15);
    tick();
  }
  if (!S.userView) autoFit(false);
  draw();
  if (S.alpha > 0.004 || S.drag || (!S.userView && S.fitting)) {
    kick();
  } else {
    savePositions(false);
  }
}

function draw() {
  for (const n of S.nodes.values()) n.el.setAttribute("transform", `translate(${n.x.toFixed(1)},${n.y.toFixed(1)})`);
  for (const l of S.links) {
    if (!l.s || !l.t) continue;
    for (const el of [l.el, l.hit]) {
      el.setAttribute("x1", l.s.x.toFixed(1)); el.setAttribute("y1", l.s.y.toFixed(1));
      el.setAttribute("x2", l.t.x.toFixed(1)); el.setAttribute("y2", l.t.y.toFixed(1));
    }
  }
  for (const f of S.flows) {
    if (!f.s || !f.t || f.el.style.display === "none") continue;
    const dx = f.t.x - f.s.x, dy = f.t.y - f.s.y;
    const d = Math.hypot(dx, dy) || 1;
    const rt = RADIUS[f.t.data.role] + 5;
    const ex = f.t.x - (dx / d) * rt, ey = f.t.y - (dy / d) * rt;
    const cx = (f.s.x + f.t.x) / 2 - (dy / d) * d * 0.18, cy = (f.s.y + f.t.y) / 2 + (dx / d) * d * 0.18;
    f.el.setAttribute("d", `M${f.s.x.toFixed(1)},${f.s.y.toFixed(1)}Q${cx.toFixed(1)},${cy.toFixed(1)} ${ex.toFixed(1)},${ey.toFixed(1)}`);
  }
}

function savePositions(force) {
  const t = Date.now();
  if (!force && t - S.lastSave < 4000) return;
  S.lastSave = t;
  const pos = {};
  for (const n of S.nodes.values()) pos[n.id] = [Math.round(n.x), Math.round(n.y), n.fx != null];
  S.savedPos = pos;
  store.set("pos", pos);
}

// ------------------------------------------------------- view & pointer
function applyView() {
  const v = S.view;
  $("viewport").setAttribute("transform", `translate(${v.x.toFixed(1)},${v.y.toFixed(1)}) scale(${v.k.toFixed(4)})`);
}

function fitTarget() {
  const nodes = [...S.nodes.values()].filter(nodeVisible);
  if (!nodes.length) return null;
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  for (const n of nodes) {
    x0 = Math.min(x0, n.x - 30); x1 = Math.max(x1, n.x + 30);
    y0 = Math.min(y0, n.y - 25); y1 = Math.max(y1, n.y + 35);
  }
  const rect = $("graph").getBoundingClientRect();
  if (rect.width < 50 || rect.height < 50) return null; // hidden tab or collapsed layout
  const k = Math.max(0.15, Math.min(1.6, (rect.width - 40) / (x1 - x0), (rect.height - 40) / (y1 - y0)));
  return { k, x: rect.width / 2 - ((x0 + x1) / 2) * k, y: rect.height / 2 - ((y0 + y1) / 2) * k };
}

function autoFit(jump) {
  const t = fitTarget();
  if (!t) return;
  const v = S.view;
  const f = jump ? 1 : 0.12;
  v.x += (t.x - v.x) * f; v.y += (t.y - v.y) * f; v.k += (t.k - v.k) * f;
  S.fitting = Math.abs(t.x - v.x) > 0.5 || Math.abs(t.y - v.y) > 0.5 || Math.abs(t.k - v.k) > 0.002;
  applyView();
}

function toGraph(e) {
  const r = $("graph").getBoundingClientRect();
  return { x: (e.clientX - r.left - S.view.x) / S.view.k, y: (e.clientY - r.top - S.view.y) / S.view.k };
}

function startDrag(e, n) {
  if (e.button !== 0) return;
  e.stopPropagation();
  const p = toGraph(e);
  // Pointer capture starts only once the node moves, so plain clicks and
  // double-clicks still reach the node.
  S.drag = { node: n, dx: n.x - p.x, dy: n.y - p.y, sx: e.clientX, sy: e.clientY, moved: false };
  hideTip();
}

function setupPointer() {
  const g = $("graph");
  g.addEventListener("pointerdown", (e) => {
    if (e.button !== 0 || S.drag) return;
    S.drag = { pan: true, sx: e.clientX, sy: e.clientY, vx: S.view.x, vy: S.view.y, moved: false };
    g.setPointerCapture(e.pointerId);
  });
  g.addEventListener("pointermove", (e) => {
    const d = S.drag;
    if (!d) return;
    if (!d.moved && Math.hypot(e.clientX - d.sx, e.clientY - d.sy) > 3) {
      d.moved = true;
      if (d.node) g.setPointerCapture(e.pointerId);
    }
    if (!d.moved) return;
    if (d.node) {
      const p = toGraph(e);
      d.node.fx = p.x + d.dx;
      d.node.fy = p.y + d.dy;
      kick();
    } else {
      g.classList.add("panning");
      S.userView = true;
      S.view.x = d.vx + e.clientX - d.sx;
      S.view.y = d.vy + e.clientY - d.sy;
      applyView();
    }
  });
  const end = () => {
    const d = S.drag;
    if (!d) return;
    S.drag = null;
    g.classList.remove("panning");
    if (d.node) {
      if (d.moved) {
        styleNode(d.node);
        savePositions(true);
      } else {
        select(d.node.id);
      }
    } else if (!d.moved) {
      select(null);
    }
  };
  g.addEventListener("pointerup", end);
  g.addEventListener("pointercancel", end);
  g.addEventListener("wheel", (e) => {
    e.preventDefault();
    const r = g.getBoundingClientRect();
    zoomAt(e.clientX - r.left, e.clientY - r.top, Math.exp(-e.deltaY * 0.0015));
  }, { passive: false });
  $("zoomIn").onclick = () => { const r = g.getBoundingClientRect(); zoomAt(r.width / 2, r.height / 2, 1.3); };
  $("zoomOut").onclick = () => { const r = g.getBoundingClientRect(); zoomAt(r.width / 2, r.height / 2, 1 / 1.3); };
  $("fit").onclick = () => { S.userView = false; S.fitting = true; kick(); };
  window.addEventListener("resize", () => { if (!S.userView) { S.fitting = true; kick(); } });
}

function zoomAt(px, py, factor) {
  const v = S.view;
  const k = Math.max(0.1, Math.min(5, v.k * factor));
  v.x = px - ((px - v.x) * k) / v.k;
  v.y = py - ((py - v.y) * k) / v.k;
  v.k = k;
  S.userView = true;
  applyView();
}

// ------------------------------------------------------------- tooltip
function showTip(e, html) {
  if (S.drag) return;
  const t = $("tooltip");
  t.innerHTML = html;
  t.hidden = false;
  moveTip(e);
}
function moveTip(e) {
  const t = $("tooltip");
  if (t.hidden) return;
  const w = t.offsetWidth, h = t.offsetHeight;
  let x = e.clientX + 14, y = e.clientY + 14;
  if (x + w > innerWidth - 8) x = e.clientX - w - 14;
  if (y + h > innerHeight - 8) y = e.clientY - h - 14;
  t.style.left = x + "px";
  t.style.top = y + "px";
}
function hideTip() { $("tooltip").hidden = true; }

function nodeTip(d) {
  const lines = [`<div class="t">${esc(nodeTitle(d))}</div>`];
  lines.push(`<div>${ROLE_NAME[d.role]} · PAN ${panHex(d.pan)}${d.vendor ? " · " + esc(d.vendor) : ""}</div>`);
  if (d.model && d.name) lines.push(`<div>${esc([d.manufacturer, d.model].filter(Boolean).join(" "))}</div>`);
  if (d.heard) {
    const sig = d.rssi != null ? fmt(d.rssi, 1, " dBFS") + " · " : "";
    lines.push(`<div>${sig}${plural(d.tx, "frame")} heard · last ${ago(d.last_tx)}</div>`);
  }
  else lines.push(`<div>Never heard transmitting (only addressed by others)</div>`);
  return lines.join("");
}

function linkTip(l) {
  const d = l.data;
  const a = S.nodes.get(d.a)?.data, b = S.nodes.get(d.b)?.data;
  if (!a || !b) return "";
  const an = esc(nodeTitle(a)), bn = esc(nodeTitle(b));
  const out = [`<div class="t">${an} ↔ ${bn}</div>`];
  if (d.parent) {
    const child = d.parent === d.a ? an : bn, parent = d.parent === d.a ? bn : an;
    out.push(`<div>End device ${child} polls its parent ${parent}</div>`);
  }
  if (d.ab || d.ba) {
    const ack = d.ack_requests ? ` · ACKed ${d.acked}/${d.ack_requests}` : "";
    out.push(`<div>Radio link: ${d.ab + d.ba} frames (${an} → ${d.ab}, ${bn} → ${d.ba})${ack}</div>`);
  }
  if (d.relay) {
    out.push(`<div>${plural(d.relay, "broadcast")} relayed straight from one to the other (radius − 1)</div>`);
  }
  if (d.route) out.push(`<div>In ${d.route} source-routed frames${d.ab || d.ba || d.relay ? "" : " (link inferred, not heard)"}</div>`);
  for (const r of d.reported || []) {
    const by = S.nodes.get(r.by)?.data;
    const who = by ? esc(nodeTitle(by)) : r.by;
    const parts = [];
    if (r.in != null) parts.push(`incoming cost ${r.in}, outgoing ${r.out || "?"}`);
    if (r.lqi != null) parts.push(`LQI ${r.lqi}${r.relationship && r.relationship !== "none" ? ", " + r.relationship : ""}`);
    if (r.routes) parts.push(`next hop for ${plural(r.routes, "route")}`);
    if (parts.length) out.push(`<div>${who} reports: ${parts.join(" · ")}</div>`);
  }
  if (d.cost != null) out.push(`<div>Link cost ${d.cost} (1 best … 7 worst)</div>`);
  out.push(`<div>Last seen ${ago(d.last_seen)}</div>`);
  return out.join("");
}

// ------------------------------------------------------------ styling
function restyle() {
  const sel = S.selected;
  const near = new Set();
  if (sel) {
    near.add(sel);
    for (const l of S.links) {
      if (l.data.a === sel) near.add(l.data.b);
      if (l.data.b === sel) near.add(l.data.a);
    }
  }
  S.near = sel ? near : null;
  for (const n of S.nodes.values()) styleNode(n);
  for (const l of S.links) styleLink(l);
  for (const f of S.flows) {
    const vis = prefs.showFlows && f.s && f.t && nodeVisible(f.s) && nodeVisible(f.t);
    f.el.style.display = vis ? "" : "none";
    f.el.classList.toggle("dim", !!sel && f.data.src !== sel && f.data.dst !== sel);
  }
  draw();
}

function styleNode(n) {
  const d = n.data, r = RADIUS[d.role];
  const g = n.el;
  g.style.display = nodeVisible(n) ? "" : "none";
  const cls = ["node", "role-" + d.role];
  if (!d.heard) cls.push("unheard");
  if (isStale(d.last_seen)) cls.push("stale");
  if (S.selected === n.id) cls.push("selected");
  if (S.near && !S.near.has(n.id)) cls.push("dim");
  g.setAttribute("class", cls.join(" "));
  g.setAttribute("aria-label", `${nodeTitle(d)}, ${ROLE_NAME[d.role]}`);
  const [pulseEl, ring, body, sel, pin, label] = g.children;
  const color = nodeColor(d);
  pulseEl.setAttribute("r", r + 1);
  body.setAttribute("d", shape(d.role, r));
  body.style.fill = d.heard ? color : "var(--surface)";
  body.style.stroke = d.heard ? "var(--surface)" : color;
  ring.setAttribute("r", r + 4.5);
  ring.style.stroke = color;
  ring.style.display = d.role === "coordinator" ? "" : "none";
  sel.setAttribute("r", r + (d.role === "coordinator" ? 8.5 : 4.5));
  pin.style.display = n.fx != null ? "" : "none";
  pin.setAttribute("cx", r * 0.9);
  pin.setAttribute("cy", -r * 0.9);
  label.setAttribute("y", r + (d.role === "coordinator" ? 18 : 13));
  label.textContent = labelFor(d);
}

function styleLink(l) {
  const d = l.data;
  const vis = linkVisible(l);
  l.el.style.display = l.hit.style.display = vis ? "" : "none";
  if (!vis) return;
  const total = d.ab + d.ba + d.relay;
  const w = d.kind === "route" ? 1.2 : 1 + Math.min(2.5, Math.log2(1 + total) / 2.2);
  l.el.setAttribute("stroke-width", w.toFixed(2));
  const cls = ["link", "kind-" + d.kind];
  if (S.selected && (d.a === S.selected || d.b === S.selected)) cls.push("hi");
  else if (S.selected) cls.push("dim");
  if (isStale(d.last_seen)) cls.push("stale");
  if (l.el.classList.contains("flash")) cls.push("flash");
  l.el.setAttribute("class", cls.join(" "));
  const byCost = prefs.linkColor === "cost" && d.cost != null;
  l.el.style.stroke = byCost ? costVar(d.cost) : "";
  if (byCost && cls.includes("hi")) l.el.setAttribute("stroke-width", (w + 1.2).toFixed(2));
}

// ------------------------------------------------------------ panels
function renderAll() {
  renderHeader();
  renderNetworks();
  renderLegend();
  renderDetails();
  renderLog();
  renderHint();
}

function refreshTimes() {
  if (!S.snap) return;
  if (S.snap.live) {
    restyle();
    renderDetails();
    renderNetworks();
  }
}

function renderHeader() {
  const snap = S.snap;
  const chip = $("source");
  const src = snap?.source || {};
  let text = "connecting…", cls = "chip";
  if (S.connected === false) {
    text = "disconnected: is zbdemod map still running?";
    cls = "chip offline";
  } else if (snap) {
    if (src.mode === "live") {
      cls = "chip live";
      text = src.channels.length > 1
        ? `Live · hopping ${src.channels.length} channels, ${src.dwell} s each · now ch ${src.current ?? "…"}`
        : `Live · channel ${src.current ?? src.channels[0]} (${mhz(src.current ?? src.channels[0])} MHz)`;
    } else {
      text = (src.mode === "pcap" ? "From PCAP" : "From recording") + (src.done ? "" : " · loading…");
    }
  }
  chip.className = cls;
  chip.lastElementChild.textContent = text;

  const st = [];
  if (snap) {
    const t = snap.totals;
    st.push(`<span class="num">${t.frames.toLocaleString()} frames</span>`);
    if (t.bad) st.push(`<span class="num">${((100 * t.bad) / t.frames).toFixed(1)} % bad FCS</span>`);
    if (src.mode === "live") {
      if (src.noise != null) st.push(`<span class="num">noise ${fmt(src.noise, 1, " dBFS")}</span>`);
      if (src.cpu != null) st.push(`<span class="num ${src.cpu > 90 ? "warn" : ""}">CPU ${src.cpu.toFixed(0)} %</span>`);
      if (src.clip > 0.1) st.push(`<span class="warn num" title="Lower the VGA gain (--vga)">clipping ${src.clip.toFixed(2)} %</span>`);
      if (src.dropped > 0.5) st.push(`<span class="warn num" title="USB samples dropped">dropped ${src.dropped.toFixed(1)} %</span>`);
    }
  }
  $("stats").innerHTML = st.join("");
  renderChannels();
}

function renderChannels() {
  const box = $("channels");
  const snap = S.snap;
  const src = snap?.source || {};
  const live = src.mode === "live" && S.connected !== false;
  if (!box.children.length) {
    for (let ch = 11; ch <= 26; ch++) {
      const b = document.createElement("button");
      b.className = "ch";
      b.dataset.ch = ch;
      b.innerHTML = `<span class="bar"></span><span class="n">${ch}</span>`;
      b.onclick = () => tune([ch]);
      box.append(b);
    }
  }
  const chans = snap?.channels || {};
  const counts = Object.values(chans).map((c) => c.frames);
  const max = Math.max(1, ...counts);
  const netsOn = {};
  for (const net of snap?.networks || []) for (const ch of net.channels) (netsOn[ch] ||= []).push(panHex(net.pan));
  for (const b of box.children) {
    const ch = +b.dataset.ch;
    const c = chans[ch];
    const frames = c ? c.frames : 0;
    b.querySelector(".bar").style.height = frames ? `${4 + (20 * Math.log1p(frames)) / Math.log1p(max)}px` : "2px";
    const current = live && src.current === ch;
    const inPlan = live && (src.channels || []).includes(ch);
    b.className = "ch" + (frames ? " heard" : "") + (netsOn[ch] ? " busy" : "") + (current ? " current" : "");
    b.disabled = !live;
    b.setAttribute("aria-pressed", String(inPlan));
    const parts = [`Channel ${ch} · ${mhz(ch)} MHz`];
    if (c) {
      parts.push(`${frames} frames${c.bad ? `, ${c.bad} bad` : ""}`);
      if (c.noise_dbfs != null) parts.push(`noise ${fmt(c.noise_dbfs, 1, " dBFS")}`);
      if (c.beacon_requests) parts.push(`${c.beacon_requests} beacon requests`);
    }
    if (netsOn[ch]) parts.push("networks " + netsOn[ch].join(", "));
    if (live) parts.push(current ? "listening now" : "click to listen here");
    b.title = parts.join("\n");
  }
  $("hopAll").disabled = !live;
  $("dwell").disabled = !live;
}

async function tune(channels) {
  try {
    const r = await fetch("api/tune", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ channels, dwell: +prefs.dwell }),
    });
    if (r.ok) S.version = "";
  } catch { setConnected(false); }
}

function renderNetworks() {
  const nets = S.snap?.networks || [];
  $("noNetworks").style.display = nets.length ? "none" : "";
  $("noNetworks").textContent = S.snap?.source?.mode === "live" ? "Listening… no networks heard yet." : "No networks in the input.";
  const ul = $("networks");
  ul.innerHTML = nets.map((net) => {
    const off = S.hidden.has(net.pan);
    const roles = net.roles || {};
    const parts = [];
    if (net.channels.length) parts.push("ch " + net.channels.join(", "));
    parts.push(`${net.nodes} device${net.nodes === 1 ? "" : "s"}`);
    if (roles.router) parts.push(`${roles.router} router${roles.router === 1 ? "" : "s"}`);
    if (roles.end_device) parts.push(`${roles.end_device} end device${roles.end_device === 1 ? "" : "s"}`);
    const badges = [];
    const keys = S.snap.decryption?.keys;
    if (net.security && keys && net.decrypted) badges.push(`<span class="badge good">decrypted</span>`);
    else if (net.security && keys && net.mic_failed) badges.push(`<span class="badge warn">key does not match</span>`);
    else if (net.security) badges.push(`<span class="badge">encrypted (NWK key)</span>`);
    else if (net.security === false) badges.push(`<span class="badge">unencrypted</span>`);
    if (net.permit_join) badges.push(`<span class="badge warn">permit join open</span>`);
    if (!net.zigbee && net.inter_pan) badges.push(`<span class="badge">Inter-PAN only</span>`);
    if (net.green_power) badges.push(`<span class="badge">Green Power</span>`);
    if (isStale(net.last_seen)) badges.push(`<span class="badge">silent ${ago(net.last_seen).replace(" ago", "")}</span>`);
    return `<li class="net${off ? " off" : ""}${S.selectedNet === net.pan ? " selected" : ""}">
      <input type="checkbox" data-toggle="${net.pan}" ${off ? "" : "checked"} aria-label="Show network ${panHex(net.pan)}">
      <button class="netbtn" data-net="${net.pan}">
        <span class="title"><span class="swatch" style="background:${slotVar(net.pan)}"></span>PAN ${panHex(net.pan)}</span>
        <span class="meta">${parts.join(" · ")}</span>
        ${net.epid ? `<span class="meta mono">${net.epid}</span>` : ""}
        <span class="badges">${badges.join("")}</span>
      </button></li>`;
  }).join("");
}

function legendShape(role, color, hollow = false, ring = false) {
  const r = RADIUS[role];
  const size = 28;
  return `<svg width="${size}" height="${size}" viewBox="${-size / 2} ${-size / 2} ${size} ${size}">
    ${ring ? `<circle r="${r + 4.5}" fill="none" stroke="${color}" stroke-width="2"/>` : ""}
    <path d="${shape(role, r)}" fill="${hollow ? "var(--surface)" : color}" stroke="${hollow ? color : "var(--surface)"}" stroke-width="2"/></svg>`;
}
function legendLine(cls) {
  return `<svg width="28" height="12" viewBox="0 0 28 12"><line class="link ${cls}" x1="2" y1="6" x2="26" y2="6" stroke-width="1.8"/></svg>`;
}

function renderLegend() {
  const c = "var(--text-2)";
  const items = [
    [legendShape("coordinator", c, false, true), "Coordinator"],
    [legendShape("router", c), "Router"],
    [legendShape("end_device", c), "End device"],
    [legendShape("unknown", c), "Role not known yet"],
    [legendShape("router", c, true), "Only addressed, never heard"],
    [legendLine("kind-radio"), "Radio link (heard)"],
    [legendLine("kind-parent"), "End device ↔ parent"],
  ];
  if (S.snap?.decryption?.keys) items.push([legendLine("kind-neighbor"), "Neighbours reported by a router"]);
  if (prefs.showRoutes) items.push([legendLine("kind-route"), "Inferred from a source route"]);
  if (prefs.showFlows) {
    items.push([`<svg width="28" height="12" viewBox="0 0 28 12"><path class="flow" d="M2,6 L22,6" marker-end="url(#arrow)"/></svg>`, "End-to-end traffic"]);
  }
  let html = items.map(([icon, text]) => `<div class="item">${icon}<span>${text}</span></div>`).join("");
  if (prefs.colorBy === "signal") {
    const [lo, hi] = S.rssiRange;
    html += `<div style="margin-top:6px">Signal at the receiver (dBFS)</div>
      <div class="ramp">${[1, 2, 3, 4, 5].map((i) => `<span style="background:var(--q${i})"></span>`).join("")}</div>
      <div class="ramp-labels num"><span>${fmt(lo, 0)}</span><span>${fmt(hi, 0)}</span></div>`;
  } else {
    html += `<div class="note" style="margin-top:6px">Colour = network (see the list above). Size and shape = role.</div>`;
  }
  if (prefs.linkColor === "cost" && S.links.some((l) => l.data.cost != null)) {
    html += `<div style="margin-top:6px">Link cost from Link Status</div>
      <div class="ramp">${[7, 5, 3, 2, 1].map((c) => `<span style="background:${costVar(c)}"></span>`).join("")}</div>
      <div class="ramp-labels num"><span>7 worst</span><span>1 best</span></div>`;
  }
  html += `<div class="note">Faded: silent for longer than the “Fade after” time. Drag to pin, double-click to release.</div>`;
  $("legend").innerHTML = html;
}

function renderHint() {
  const hint = $("hint");
  const snap = S.snap;
  if (snap && snap.nodes.length) {
    hint.style.display = "none";
    return;
  }
  hint.style.display = "";
  const src = snap?.source || {};
  if (!snap) hint.innerHTML = `<strong>Connecting…</strong>`;
  else if (src.mode === "live")
    hint.innerHTML = `<strong>Listening…</strong>Devices appear as they transmit. Routers announce themselves about every 15 s.<br>
      No network on this channel? Try <em>Hop all</em> above.`;
  else hint.innerHTML = src.done ? `<strong>No 802.15.4 networks found in the input.</strong>` : `<strong>Loading…</strong>`;
}

function kv(rows) {
  return `<dl class="kv">${rows.filter((r) => r && r[1] != null && r[1] !== "").map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>`;
}

function renderDetails() {
  const box = $("details");
  const snap = S.snap;
  if (!snap) { box.innerHTML = ""; return; }
  const n = S.selected && S.nodes.get(S.selected);
  if (n) { box.innerHTML = nodeDetails(n.data); return; }
  const net = S.selectedNet != null && snap.networks.find((x) => x.pan === S.selectedNet);
  if (net) { box.innerHTML = networkDetails(net); return; }
  const ev = [...snap.events].reverse().slice(0, 40);
  box.innerHTML = `<h2 style="margin-top:2px">Recent events</h2>
    ${ev.length ? `<ul class="events">${ev.map((e) => `<li>${e.node ? `<button class="linkish" data-node="${esc(e.node)}">${esc(e.text)}</button>` : esc(e.text)}<time>${clock(e.t)} · ${ago(e.t)}</time></li>`).join("")}</ul>` : `<p class="empty">Nothing yet.</p>`}
    <p class="note" style="margin-top:14px">Click a device or a network for details. ${snap.decryption?.keys
      ? "Frames are decrypted with your network key: router neighbour tables, link costs, device announcements and ZCL Basic attributes are included."
      : "Everything here comes from unencrypted headers. Start with --keys FILE to decrypt with your own network key."}</p>`;
}

function nodeDetails(d) {
  const byId = new Map(S.snap.nodes.map((x) => [x.id, x]));
  const hops = Object.entries(d.hops || {}).map(([origin, h]) => {
    const o = byId.get(origin);
    const who = o ? (o.role === "coordinator" ? "coordinator" : esc(nodeTitle(o))) : origin;
    return `${h} from ${who}`;
  });
  const neighbours = S.links
    .filter((l) => l.data.a === d.id || l.data.b === d.id)
    .map((l) => {
      const other = byId.get(l.data.a === d.id ? l.data.b : l.data.a);
      const KIND = { route: "inferred", neighbor: "neighbour", radio: "radio" };
      const kind = l.data.parent ? (l.data.parent === d.id ? "child" : "parent") : KIND[l.data.kind] || l.data.kind;
      const mine = l.data.a === d.id ? l.data.ab : l.data.ba, theirs = l.data.a === d.id ? l.data.ba : l.data.ab;
      return { other, kind, mine, theirs, relay: l.data.relay, cost: l.data.cost, last: l.data.last_seen };
    })
    .filter((x) => x.other)
    .sort((a, b) => ROLE_RANK[b.other.role] - ROLE_RANK[a.other.role] || b.mine + b.theirs - a.mine - a.theirs);
  const ev = d.evidence.filter((e) => e.reason);
  return `<div class="panel-head">
      <span class="swatch" style="margin-top:5px;background:${nodeColor(d)}"></span>
      <div><h3>${esc(nodeTitle(d))}</h3><div class="sub">${ROLE_NAME[d.role]} · <button class="linkish" data-net="${d.pan}">PAN ${panHex(d.pan)}</button></div></div>
      <button class="close" data-close aria-label="Close">×</button>
    </div>
    ${kv([
      ["Short address", d.short ? `<span class="mono">${d.short}</span>` : "not known"],
      ["IEEE address", d.ieee ? `<span class="mono">${d.ieee}</span>` : "not seen yet"],
      ["Vendor (OUI)", d.vendor ? esc(d.vendor) : d.ieee ? `unknown (<span class="mono">${d.ieee.slice(0, 8)}</span>)` : null],
      ["Name", d.name ? esc(d.name) : null],
      ["Manufacturer", d.manufacturer ? esc(d.manufacturer) : d.manufacturer_code != null ? `code 0x${d.manufacturer_code.toString(16).padStart(4, "0")}` : null],
      ["Model", d.model ? esc(d.model) : null],
      ["Firmware", d.sw_build ? esc(d.sw_build) : null],
      ["Power", d.power_source ? esc(d.power_source) : d.mains == null ? null : d.mains ? "mains" : "battery"],
      ["Clusters", d.clusters?.length ? esc(d.clusters.join(", ")) : null],
      ["Controls", d.controls?.length ? esc(d.controls.join(", ")) : null],
      ["Concentrator", d.concentrator ? "yes (many-to-one routing)" : null],
      ["Left network", d.left ? `${clock(d.left)} · ${ago(d.left)}` : null],
      ["Hops", hops.length ? hops.join(", ") : null],
      ["Beacon depth", d.depth],
      ["Channel", d.channel],
      ["Signal", !d.heard ? "never heard transmitting" : d.rssi != null ? `${fmt(d.rssi, 1, " dBFS")} · SNR ${fmt(d.snr, 1, " dB")}` : null],
      ["Freq. offset", d.cfo_khz != null ? fmt(d.cfo_khz, 1, " kHz") : null],
      ["LQI", d.lqi != null ? Math.round(d.lqi) : null],
      ["Frames", `${d.tx} heard from it · ${d.rx} addressed to it`],
      ["NWK frame ctr", d.frame_counter != null ? d.frame_counter.toLocaleString() : null],
      ["Receiver idle", d.rx_on_when_idle == null ? null : d.rx_on_when_idle ? "on (mains powered)" : "off (sleepy)"],
      ["Permit join", d.permit_join == null ? null : d.permit_join ? "open" : "closed"],
      ["First seen", `${clock(d.first_seen)}`],
      ["Last heard", d.last_tx ? `${clock(d.last_tx)} · ${ago(d.last_tx)}` : "—"],
    ])}
    <h2>Why this role</h2>
    ${ev.length ? `<ul class="evidence">${ev.map((e) => `<li>${esc(e.reason)}</li>`).join("")}</ul>` : `<p class="empty">No evidence yet: the device has not sent a frame that reveals its role.</p>`}
    <h2>Neighbours (${neighbours.length})</h2>
    ${neighbours.length ? `<table class="tbl"><thead><tr><th>Device</th><th>Link</th><th class="r">Cost</th><th class="r">Frames</th></tr></thead><tbody>
      ${neighbours.map((x) => `<tr data-node="${esc(x.other.id)}"><td>${esc(nodeTitle(x.other))}<div class="note">${ROLE_NAME[x.other.role]}</div></td>
        <td>${x.kind}${x.relay ? ` · ${plural(x.relay, "relay")}` : ""}</td><td class="r">${x.cost ?? "—"}</td><td class="r">${x.mine} → / ${x.theirs} ←</td></tr>`).join("")}
      </tbody></table>` : `<p class="empty">No links seen yet.</p>`}`;
}

function networkDetails(net) {
  const devices = S.snap.nodes.filter((d) => d.pan === net.pan)
    .sort((a, b) => ROLE_RANK[b.role] - ROLE_RANK[a.role] || (b.rssi ?? -999) - (a.rssi ?? -999));
  const roles = net.roles || {};
  const ROLE_COUNT = { coordinator: "coordinator", router: "router", end_device: "end device" };
  const roleText = Object.entries(roles).filter(([, v]) => v)
    .map(([k, v]) => (k === "unknown" ? `${v} of unknown role` : plural(v, ROLE_COUNT[k]))).join(", ");
  return `<div class="panel-head">
      <span class="swatch" style="margin-top:5px;background:${slotVar(net.pan)}"></span>
      <div><h3>PAN ${panHex(net.pan)}</h3><div class="sub">${net.zigbee ? "Zigbee network" : "802.15.4 network"}</div></div>
      <button class="close" data-close aria-label="Close">×</button>
    </div>
    ${kv([
      ["Channel", net.channels.map((c) => `${c} (${mhz(c)} MHz)`).join(", ")],
      ["Extended PAN ID", net.epid ? `<span class="mono">${net.epid}</span>` : "not seen (needs a beacon)"],
      ["Stack profile", net.stack_profile],
      ["Security", net.security ? `NWK encryption, key sequence ${net.key_seq ?? "?"}` : net.security === false ? "none seen" : null],
      ["Decryption", !net.security ? null : !S.snap.decryption?.keys ? "no key configured (--keys)"
        : `${net.decrypted.toLocaleString()} frames decrypted${net.mic_failed ? `, ${net.mic_failed.toLocaleString()} did not match any key` : ""}${net.aps_encrypted ? `, ${net.aps_encrypted} APS-encrypted (link key, not decrypted)` : ""}`],
      ["Permit join", net.permit_join ? "open (seen in a beacon)" : null],
      ["Devices", `${net.nodes}${roleText ? " · " + roleText : ""}`],
      ["Frames", net.frames.toLocaleString()],
      ["Green Power", net.green_power || null],
      ["Inter-PAN", net.inter_pan || null],
      ["First seen", clock(net.first_seen)],
      ["Last seen", `${clock(net.last_seen)} · ${ago(net.last_seen)}`],
    ])}
    <h2>Devices</h2>
    <table class="tbl"><thead><tr><th>Device</th><th>Role</th><th class="r">Signal</th><th class="r">Last heard</th></tr></thead><tbody>
      ${devices.map((d) => `<tr data-node="${esc(d.id)}"><td>${esc(nodeTitle(d))}${d.model || d.vendor ? `<div class="note">${esc(d.model && d.name ? d.model : d.manufacturer || d.vendor || "")}</div>` : ""}</td>
        <td>${ROLE_NAME[d.role]}</td><td class="r">${d.heard ? fmt(d.rssi, 0) : "—"}</td><td class="r">${d.last_tx ? ago(d.last_tx).replace(" ago", "") : "—"}</td></tr>`).join("")}
    </tbody></table>`;
}

function renderLog() {
  const snap = S.snap;
  if (!snap || !prefs.logOpen) return;
  const pre = $("log");
  const atBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 20;
  let lines = snap.log;
  const n = S.selected && S.nodes.get(S.selected)?.data;
  if (n) {
    const keys = [n.short, n.ieee].filter(Boolean);
    lines = lines.filter((l) => keys.some((k) => l.text.includes(k)));
    $("logNote").textContent = `showing frames that mention ${keys.join(" / ")}`;
  } else {
    $("logNote").textContent = `last ${lines.length} frames`;
  }
  pre.textContent = lines.map((l) => `${clock(l.t)}  ${l.ch ? "ch" + l.ch : "    "}  ${l.rssi != null ? l.rssi.toFixed(1).padStart(6) : "      "}  ${l.text}`).join("\n");
  if (atBottom) pre.scrollTop = pre.scrollHeight;
}

// ----------------------------------------------------------- actions
function select(id) {
  S.selected = id;
  if (id) S.selectedNet = null;
  restyle();
  renderDetails();
  renderLog();
  renderNetworks();
}
function selectNet(pan) {
  S.selectedNet = pan;
  S.selected = null;
  restyle();
  renderDetails();
  renderLog();
  renderNetworks();
}

function setupControls() {
  const bind = (id, key, parse = (v) => v) => {
    const el = $(id);
    if (el.type === "checkbox") el.checked = !!prefs[key];
    else el.value = String(prefs[key]);
    el.addEventListener("change", () => {
      prefs[key] = el.type === "checkbox" ? el.checked : parse(el.value);
      store.set("prefs", prefs);
      restyle();
      renderAll();
      reheat(0.2);
    });
  };
  bind("colorBy", "colorBy");
  bind("linkColor", "linkColor");
  bind("labelBy", "labelBy");
  bind("staleAfter", "staleAfter", Number);
  bind("showRoutes", "showRoutes");
  bind("showFlows", "showFlows");
  bind("hideStale", "hideStale");
  bind("dwell", "dwell", Number);
  $("hopAll").onclick = () => tune("11-26");
  $("unpin").onclick = () => {
    for (const n of S.nodes.values()) n.fx = n.fy = null;
    restyle();
    reheat(0.5);
    savePositions(true);
  };
  $("reset").onclick = async () => {
    if (!confirm("Forget every network and device heard so far?")) return;
    try {
      await fetch("api/reset", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      S.version = "";
    } catch { setConnected(false); }
  };
  $("logToggle").onclick = () => {
    prefs.logOpen = !prefs.logOpen;
    store.set("prefs", prefs);
    applyLogState();
    renderLog();
  };
  applyLogState();

  document.addEventListener("click", (e) => {
    const t = e.target.closest("[data-node],[data-net],[data-close],[data-toggle]");
    if (!t) return;
    if (t.dataset.close !== undefined) { S.selected = null; S.selectedNet = null; select(null); return; }
    if (t.dataset.toggle !== undefined) {
      const pan = +t.dataset.toggle;
      if (t.checked) S.hidden.delete(pan); else S.hidden.add(pan);
      store.set("hidden", [...S.hidden]);
      restyle();
      renderNetworks();
      reheat(0.3);
      return;
    }
    if (t.dataset.node !== undefined) {
      const id = t.dataset.node;
      if (S.nodes.has(id)) select(id);
      return;
    }
    if (t.dataset.net !== undefined) selectNet(+t.dataset.net);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { S.selectedNet = null; select(null); }
  });
}

function applyLogState() {
  $("logPanel").classList.toggle("closed", !prefs.logOpen);
  $("logToggle").textContent = (prefs.logOpen ? "▾" : "▸") + " Frames";
  $("logToggle").setAttribute("aria-expanded", String(prefs.logOpen));
}

setupPointer();
setupControls();
renderAll();
applyView();
poll();
