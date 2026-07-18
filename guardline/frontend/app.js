/* ============================================================
   Guardline frontend
   - Web Speech API: live transcription of room audio
   - Web Audio AnalyserNode: real mic amplitude drives the orb
   - Canvas: a fluid, audio-reactive "Siri" orb
   - /check  : semantic scam match via Moss, rendered as alerts
   - /stats  : threat-library coverage panel
   - /ingest : live Bright Data scrape that grows the library
   Served same-origin from the backend (http://localhost:3000).
   ============================================================ */

const body = document.body;
const statusEl = document.getElementById("status");
const hintEl = document.getElementById("hint");
const micBtn = document.getElementById("mic-btn");
const replayBtn = document.getElementById("replay-btn");
const transcriptWrap = document.getElementById("transcript-wrap");
const transcriptEl = document.getElementById("transcript");
const alertsEl = document.getElementById("alerts");
const unsupportedEl = document.getElementById("unsupported");
const canvas = document.getElementById("orb");
const ctx = canvas.getContext("2d");

// library panel
const libCountEl = document.getElementById("lib-count");
const libCategoriesEl = document.getElementById("lib-categories");
const libSourcesEl = document.getElementById("lib-sources");
const updateLibBtn = document.getElementById("update-lib");

// threat meter
const threatEl = document.getElementById("threat");
const threatValueEl = document.getElementById("threat-value");
const threatFillEl = document.getElementById("threat-fill");

const SpeechRecognition =
  window.SpeechRecognition || window.webkitSpeechRecognition;

let recognition = null;
let listening = false;
let replaying = false;

/* audio analysis */
let audioCtx = null;
let analyser = null;
let micStream = null;
let freqData = null;

/* smoothed drivers for the orb */
let level = 0;
let alertLevel = 0;

/* threat accumulation over the call (0..100) */
let threatScore = 0;

/* alert bookkeeping: one card per category, re-fires pulse */
const alertCards = new Map();
let alertResetTimer = null;

const CATEGORY_LABELS = {
  irs: "IRS Impersonation",
  tech_support: "Tech-Support Scam",
  grandparent: "Grandparent Scam",
  medicare: "Medicare Scam",
  utility_shutoff: "Utility Shut-off Scam",
  bank_impersonation: "Bank Impersonation",
  social_security: "Social Security Scam",
};

const SOURCE_LABELS = {
  aarp: "AARP Fraud Watch",
  bbb: "BBB Scam Alert",
  ftc: "FTC Consumer Advice",
};

/* ---------------- status ---------------- */
function setStatus(text, hint) {
  statusEl.textContent = text;
  if (hint !== undefined) hintEl.textContent = hint;
}

/* ---------------- library / coverage panel ---------------- */
async function loadStats(bump = false) {
  try {
    const res = await fetch("/stats");
    if (!res.ok) return;
    const s = await res.json();
    if (bump) {
      libCountEl.classList.remove("bump");
      void libCountEl.offsetWidth;
      libCountEl.classList.add("bump");
    }
    libCountEl.textContent = s.patternCount;
    libCategoriesEl.textContent = `${s.categoryCount} categories`;
    libSourcesEl.textContent =
      "sources " + (s.sources || []).map((x) => x.toUpperCase()).join(", ");
  } catch {
    /* offline — leave placeholders */
  }
}

async function updateLibrary() {
  updateLibBtn.disabled = true;
  updateLibBtn.classList.add("is-loading");
  const original = hintEl.textContent;
  setStatus(statusEl.textContent, "Scraping the latest scam alerts live via Bright Data…");
  try {
    const res = await fetch("/ingest", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    const r = await res.json();
    if (r.added > 0 && r.patterns && r.patterns[0]) {
      const p = r.patterns[0];
      const label = CATEGORY_LABELS[p.category] || p.category;
      await loadStats(true);
      setStatus(statusEl.textContent, `＋ Learned a new scam type — ${label} — scraped live from ${(p.source || "").toUpperCase()} via Bright Data.`);
    } else if (r.exhausted) {
      setStatus(statusEl.textContent, "Threat library is fully up to date.");
    } else {
      setStatus(statusEl.textContent, original);
    }
  } catch {
    setStatus(statusEl.textContent, "Couldn't reach the scrape service.");
  } finally {
    updateLibBtn.disabled = false;
    updateLibBtn.classList.remove("is-loading");
  }
}

/* ---------------- threat meter ---------------- */
function bumpThreat(severity) {
  threatScore = Math.min(100, threatScore + (severity || 2) * 22);
  renderThreat();
}
function decayThreat() {
  threatScore = Math.max(0, threatScore - 7);
  renderThreat();
}
function resetThreat() {
  threatScore = 0;
  renderThreat();
}
function renderThreat() {
  threatFillEl.style.width = `${threatScore}%`;
  let level = "low";
  let label = "Low";
  if (threatScore >= 66) { level = "high"; label = "High"; }
  else if (threatScore >= 30) { level = "elevated"; label = "Elevated"; }
  threatEl.dataset.level = level;
  threatValueEl.textContent = label;
}

/* ---------------- speech recognition ---------------- */
function initRecognition() {
  recognition = new SpeechRecognition();
  recognition.continuous = true;
  recognition.interimResults = true;
  recognition.lang = "en-US";

  recognition.onresult = (event) => {
    let interim = "";
    let finalText = "";
    for (let i = event.resultIndex; i < event.results.length; i++) {
      const r = event.results[i];
      if (r.isFinal) finalText += r[0].transcript;
      else interim += r[0].transcript;
    }
    const display = (finalText || interim).trim();
    if (display) transcriptEl.textContent = display;
    if (finalText.trim()) checkSegment(finalText);
  };

  recognition.onerror = (event) => {
    if (event.error === "not-allowed" || event.error === "service-not-allowed") {
      setStatus("Microphone blocked", "Allow mic access and reload to continue.");
      stopListening();
    }
  };

  recognition.onend = () => {
    if (listening) {
      try { recognition.start(); } catch { /* already starting */ }
    }
  };
}

/* ---------------- audio-reactive analyser ---------------- */
async function startAudio() {
  try {
    micStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const src = audioCtx.createMediaStreamSource(micStream);
    analyser = audioCtx.createAnalyser();
    analyser.fftSize = 512;
    analyser.smoothingTimeConstant = 0.8;
    src.connect(analyser);
    freqData = new Uint8Array(analyser.frequencyBinCount);
  } catch (err) {
    console.warn("Audio analyser unavailable:", err);
  }
}

function stopAudio() {
  if (micStream) micStream.getTracks().forEach((t) => t.stop());
  if (audioCtx) audioCtx.close().catch(() => {});
  micStream = null;
  audioCtx = null;
  analyser = null;
  freqData = null;
}

function sampleLevel() {
  if (!analyser || !freqData) return 0;
  analyser.getByteFrequencyData(freqData);
  let sum = 0;
  const start = 2;
  const end = Math.min(freqData.length, 96);
  for (let i = start; i < end; i++) sum += freqData[i];
  const avg = sum / (end - start) / 255;
  return Math.min(1, avg * 1.9);
}

/* ---------------- the orb (verified) ---------------- */
let dpr = Math.min(window.devicePixelRatio || 1, 2);

function resizeCanvas() {
  const rect = canvas.getBoundingClientRect();
  dpr = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = Math.round(rect.width * dpr);
  canvas.height = Math.round(rect.height * dpr);
}

function mix(a, b, t) {
  return [
    Math.round(a[0] + (b[0] - a[0]) * t),
    Math.round(a[1] + (b[1] - a[1]) * t),
    Math.round(a[2] + (b[2] - a[2]) * t),
  ];
}

const CALM = [[47, 230, 214], [106, 92, 255], [64, 200, 255]];
const ALERT = [[255, 90, 77], [255, 176, 32], [255, 60, 60]];

function drawBlob(cx, cy, baseR, t, seed, wob, amp, color, alpha) {
  const POINTS = 64;
  const pts = [];
  for (let i = 0; i < POINTS; i++) {
    const a = (i / POINTS) * Math.PI * 2;
    let r = baseR;
    r += Math.sin(a * 3 + t * 0.9 + seed) * wob;
    r += Math.sin(a * 5 - t * 1.3 + seed * 1.7) * wob * 0.5;
    r += Math.sin(a * 2 + t * 1.6 + seed) * amp * 0.5;
    r += amp;
    pts.push([cx + Math.cos(a) * r, cy + Math.sin(a) * r]);
  }
  ctx.beginPath();
  const last = pts[POINTS - 1];
  const first = pts[0];
  ctx.moveTo((last[0] + first[0]) / 2, (last[1] + first[1]) / 2);
  for (let i = 0; i < POINTS; i++) {
    const p = pts[i];
    const n = pts[(i + 1) % POINTS];
    ctx.quadraticCurveTo(p[0], p[1], (p[0] + n[0]) / 2, (p[1] + n[1]) / 2);
  }
  ctx.closePath();
  const grad = ctx.createRadialGradient(cx, cy, baseR * 0.1, cx, cy, baseR * 1.15);
  const [r, g, b] = color;
  grad.addColorStop(0, `rgba(${r},${g},${b},${alpha})`);
  grad.addColorStop(0.6, `rgba(${r},${g},${b},${alpha * 0.55})`);
  grad.addColorStop(1, `rgba(${r},${g},${b},0)`);
  ctx.fillStyle = grad;
  ctx.fill();
}

let startTime = performance.now();

function render(now) {
  const t = (now - startTime) / 1000;
  const active = listening || replaying;
  const targetLevel = active ? sampleLevel() : 0;
  level += (targetLevel - level) * 0.12;
  const alertTarget = body.dataset.state === "alert" ? 1 : 0;
  alertLevel += (alertTarget - alertLevel) * 0.06;

  const w = canvas.width, h = canvas.height;
  const cx = w / 2, cy = h / 2;
  const unit = Math.min(w, h);
  ctx.clearRect(0, 0, w, h);

  const breathe = 0.5 + 0.5 * Math.sin(t * 1.1);
  const energy = active ? 0.35 + level * 0.9 : 0.14 + breathe * 0.08;
  const baseR = unit * (0.26 + energy * 0.05);
  const amp = unit * 0.05 * energy;
  const wob = unit * (0.018 + energy * 0.03);

  const c0 = mix(CALM[0], ALERT[0], alertLevel);
  const c1 = mix(CALM[1], ALERT[1], alertLevel);
  const c2 = mix(CALM[2], ALERT[2], alertLevel);

  const halo = ctx.createRadialGradient(cx, cy, baseR * 0.4, cx, cy, unit * 0.6);
  halo.addColorStop(0, `rgba(${c0[0]},${c0[1]},${c0[2]},${0.18 + energy * 0.15})`);
  halo.addColorStop(1, "rgba(0,0,0,0)");
  ctx.fillStyle = halo;
  ctx.fillRect(0, 0, w, h);

  ctx.globalCompositeOperation = "lighter";
  drawBlob(cx, cy, baseR, t, 0.0, wob, amp, c1, 0.5);
  drawBlob(cx + amp * 0.3, cy - amp * 0.2, baseR * 0.92, t * 1.15, 2.1, wob, amp, c0, 0.55);
  drawBlob(cx - amp * 0.2, cy + amp * 0.25, baseR * 0.82, t * 0.85, 4.3, wob, amp, c2, 0.45);

  const core = ctx.createRadialGradient(cx, cy, 0, cx, cy, baseR * 0.7);
  core.addColorStop(0, `rgba(255,255,255,${0.28 + level * 0.4})`);
  core.addColorStop(0.5, `rgba(${c0[0]},${c0[1]},${c0[2]},0.18)`);
  core.addColorStop(1, "rgba(0,0,0,0)");
  ctx.fillStyle = core;
  ctx.fillRect(cx - baseR, cy - baseR, baseR * 2, baseR * 2);
  ctx.globalCompositeOperation = "source-over";

  requestAnimationFrame(render);
}

/* ---------------- detection ---------------- */
async function checkSegment(text) {
  const trimmed = text.trim();
  if (!trimmed) return;
  try {
    const res = await fetch("/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: trimmed }),
    });
    if (!res.ok) return;
    const result = await res.json();
    if (result.matched) {
      transcriptEl.innerHTML = highlightTerms(trimmed, result.matched_terms || []);
      bumpThreat(result.severity);
      showAlert(result);
    } else {
      decayThreat();
    }
  } catch (err) {
    console.warn("Could not reach backend:", err);
  }
}

function highlightTerms(text, terms) {
  const uniq = [...new Set(terms.map((t) => t.toLowerCase()))].filter(Boolean);
  const lower = text.toLowerCase();
  const ranges = [];
  for (const term of uniq) {
    let i = 0;
    while ((i = lower.indexOf(term, i)) !== -1) {
      ranges.push([i, i + term.length]);
      i += term.length;
    }
  }
  ranges.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const r of ranges) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1]) last[1] = Math.max(last[1], r[1]);
    else merged.push([...r]);
  }
  let out = "", pos = 0;
  for (const [s, e] of merged) {
    out += escapeHtml(text.slice(pos, s)) + `<span class="trigger-hit">${escapeHtml(text.slice(s, e))}</span>`;
    pos = e;
  }
  out += escapeHtml(text.slice(pos));
  return out;
}

/* ---------------- alerts ---------------- */
function showAlert(result) {
  body.dataset.state = "alert";
  scheduleAlertReset();

  const category = result.category || "unknown";
  if (alertCards.has(category)) {
    const existing = alertCards.get(category);
    existing.classList.remove("alert-card--pulse");
    void existing.offsetWidth;
    existing.classList.add("alert-card--pulse");
    return;
  }

  const label = CATEGORY_LABELS[category] || formatCategory(category);
  const pct = typeof result.confidence === "number" ? Math.round(result.confidence * 100) : null;
  const srcLabel = SOURCE_LABELS[result.source] || "Verified source";
  const actions = (result.actions || []).slice(0, 4);

  const card = document.createElement("article");
  card.className = "alert-card";
  card.innerHTML = `
    <div class="alert-card__top">
      <span class="alert-card__badge">Likely scam</span>
      <span class="alert-card__category">${escapeHtml(label)}${result.subtype ? " · " + escapeHtml(result.subtype) : ""}</span>
      <span class="alert-card__meta">
        <b>Moss</b> ${result.timeTakenInMs != null ? `· ${result.timeTakenInMs} ms` : ""} ${pct != null ? `· ${pct}%` : ""}
      </span>
    </div>
    <p class="alert-card__fact">${escapeHtml(result.real_fact || "")}</p>
    ${
      actions.length
        ? `<div class="alert-card__actions">
             <p class="alert-card__actions-label">What to do now</p>
             <ul>${actions.map((a) => `<li>${escapeHtml(a)}</li>`).join("")}</ul>
           </div>`
        : ""
    }
    <div class="alert-card__foot">
      ${
        result.source_url
          ? `<a class="alert-card__source" href="${escapeAttr(result.source_url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(srcLabel)} <b>· via Bright Data</b></a>`
          : "<span></span>"
      }
      <button type="button" class="alert-card__dismiss">Dismiss</button>
    </div>
  `;

  card.querySelector(".alert-card__dismiss").addEventListener("click", () => {
    card.remove();
    alertCards.delete(category);
    if (alertCards.size === 0 && (listening || replaying)) body.dataset.state = "listening";
  });

  alertsEl.prepend(card);
  alertCards.set(category, card);
}

function scheduleAlertReset() {
  clearTimeout(alertResetTimer);
  alertResetTimer = setTimeout(() => {
    if (listening || replaying) body.dataset.state = "listening";
  }, 9000);
}

function formatCategory(c) {
  return String(c).replace(/_/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
}
function escapeHtml(str) {
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function escapeAttr(str) {
  return escapeHtml(str).replace(/'/g, "&#39;");
}

/* ---------------- listen toggle ---------------- */
async function startListening() {
  if (listening || replaying) return;
  listening = true;
  micBtn.setAttribute("aria-pressed", "true");
  micBtn.setAttribute("aria-label", "Stop listening");
  body.dataset.state = "listening";
  transcriptWrap.hidden = false;
  threatEl.hidden = false;
  resetThreat();
  setStatus("Listening for scam patterns…", "Guardline never speaks — it watches silently.");
  await startAudio();
  try { recognition.start(); } catch { /* already started */ }
}

function stopListening() {
  if (!listening) return;
  listening = false;
  micBtn.setAttribute("aria-pressed", "false");
  micBtn.setAttribute("aria-label", "Start listening");
  body.dataset.state = "idle";
  setStatus("Protection paused", "Tap the orb to resume listening.");
  try { recognition.stop(); } catch { /* ignore */ }
  stopAudio();
}

/* ---------------- replay (mic-independent demo fallback) ---------------- */
const REPLAY_LINES = [
  "Hello, am I speaking with the account holder? This is the tax department calling.",
  "Our records show you have unpaid back taxes going back three years.",
  "There is now a warrant out for your arrest, and officers are being dispatched to your address today.",
  "The only way to stop this is to settle the balance immediately using gift cards.",
  "Do not hang up or tell anyone, or the police will proceed with the arrest.",
];

async function runReplay() {
  if (listening || replaying) return;
  replaying = true;
  replayBtn.disabled = true;
  micBtn.disabled = true;
  body.dataset.state = "listening";
  transcriptWrap.hidden = false;
  threatEl.hidden = false;
  resetThreat();
  setStatus("Sample scam call in progress…", "Replaying a scripted call — no microphone needed.");

  for (const line of REPLAY_LINES) {
    transcriptEl.textContent = line;
    await checkSegment(line);
    await sleep(2000);
  }

  setStatus("Sample call complete", "That call escalated to a high-confidence IRS scam. Tap the orb to protect a real call.");
  replaying = false;
  replayBtn.disabled = false;
  micBtn.disabled = false;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/* ---------------- init ---------------- */
function init() {
  resizeCanvas();
  window.addEventListener("resize", resizeCanvas);
  requestAnimationFrame(render);
  renderThreat();
  loadStats();

  updateLibBtn.addEventListener("click", updateLibrary);
  replayBtn.addEventListener("click", runReplay);

  if (!SpeechRecognition) {
    setStatus("Live mic needs Chrome", "You can still use “Replay a sample scam call” below.");
    micBtn.disabled = true;
    unsupportedEl.hidden = false;
    unsupportedEl.textContent =
      "The Web Speech API isn't available in this browser. Open Guardline in Google Chrome for live listening — the replay demo works anywhere.";
  } else {
    initRecognition();
    micBtn.addEventListener("click", () => {
      if (listening) stopListening();
      else startListening();
    });
  }
}

init();
