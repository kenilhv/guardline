import "dotenv/config";
import express from "express";
import cors from "cors";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { indexPatterns, addDocs, queryPattern } from "./moss-client.js";
import { fetchMarkdown, extractPatterns } from "./brightdata.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const patternsPath = join(__dirname, "..", "data", "scam-patterns.json");

// The in-memory source of truth. Moss matches and returns an id; we join here
// to the full record (actions, real_fact, severity…). Live-ingested patterns
// (see /ingest) are appended here and re-indexed, so they behave identically.
let patterns = JSON.parse(readFileSync(patternsPath, "utf-8"));
let patternById = new Map(patterns.map((p) => [p.id, p]));

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Serve the frontend from the same origin as the API so the mic APIs work
// (getUserMedia / AudioContext are blocked on file:// origins).
app.use(express.static(join(__dirname, "..", "frontend")));

let mossReady = false;

/* ---------------- risk vocabulary + lexical gate ----------------
   With a modest index, raw embedding scores compress high for almost any short
   sentence, so a semantic hit alone isn't a reliable alert. We require real
   scam vocabulary to ALSO be present. The vocabulary is corpus-driven: every
   pattern's trigger_terms, plus a base list of universally suspicious phrases. */
const BASE_RISK_TERMS = [
  "gift card", "prepaid", "wire", "wired", "wire transfer", "cryptocurrency",
  "social security", "ssn", "bank account", "routing number", "password",
  "arrest", "warrant", "lawsuit", "jail", "bail", "police", "sheriff",
  "back taxes", "irs", "medicare", "suspended", "verify", "confirm",
  "remote access", "virus", "hackers", "shut off", "disconnected",
  "gift cards", "pay now", "pay immediately", "act now", "don't tell",
  "safe account", "move your money", "refund", "overdue",
];

let riskTerms = buildRiskTerms(patterns);

function buildRiskTerms(pats) {
  const set = new Set(BASE_RISK_TERMS);
  for (const p of pats) for (const t of p.trigger_terms || []) set.add(t.toLowerCase());
  return [...set];
}

// Returns the specific terms that appear in the text — used both to gate the
// alert and to highlight the triggering words in the live transcript.
function findRiskTerms(text, extraTerms = []) {
  const haystack = (text || "").toLowerCase();
  const terms = new Set([...riskTerms, ...extraTerms.map((t) => t.toLowerCase())]);
  const hits = [];
  for (const t of terms) if (t && haystack.includes(t)) hits.push(t);
  // longest first so multi-word phrases highlight before their sub-words
  return hits.sort((a, b) => b.length - a.length);
}

/* ---------------- stub fallback matcher ----------------
   Used only if Moss is unavailable. Keyword overlap against pattern text so the
   demo still works with the same id-join path. */
function stubMatch(text) {
  const haystack = (text || "").toLowerCase();
  if (!haystack.trim()) return { matched: false };
  for (const p of patterns) {
    const phrases = [...(p.example_phrases || []), ...(p.trigger_terms || []), p.pattern_text || ""];
    for (const phrase of phrases) {
      const needle = String(phrase).toLowerCase();
      if (needle && (haystack.includes(needle) || wordsOverlap(haystack, needle))) {
        return { matched: true, id: p.id, score: 0.8 };
      }
    }
  }
  return { matched: false };
}

function wordsOverlap(haystack, needle) {
  const words = needle.split(/\s+/).map((w) => w.replace(/[^a-z0-9]/g, "")).filter((w) => w.length >= 4);
  return words.filter((w) => haystack.includes(w)).length >= 2;
}

// Build the full alert payload from a matched pattern id.
function buildAlert(match, text) {
  const p = patternById.get(match.id);
  if (!p) return { matched: false };
  const matched_terms = findRiskTerms(text, p.trigger_terms);
  return {
    matched: true,
    pattern_id: p.id,
    category: p.category,
    subtype: p.subtype,
    confidence: match.score,
    severity: p.severity ?? 2,
    real_fact: p.real_fact,
    actions: p.actions || [],
    matched_terms,
    source_url: p.source_url,
    source: p.source,
    timeTakenInMs: match.timeTakenInMs,
  };
}

app.post("/check", async (req, res) => {
  const text = req.body?.text;
  if (typeof text !== "string") {
    return res.status(400).json({ error: "Body must be { text: string }" });
  }

  const hasRisk = findRiskTerms(text).length > 0;

  let match;
  let engine;
  if (mossReady) {
    try {
      match = await queryPattern(text);
      engine = "moss";
    } catch (err) {
      console.error("/check: Moss query failed, falling back to stub:", err.message);
    }
  }
  if (!match) {
    match = stubMatch(text);
    engine = "stub";
  }

  // Gate: alert only when the engine matched AND real scam vocabulary is present.
  if (!match.matched || !hasRisk) {
    return res.json({ matched: false, engine, timeTakenInMs: match.timeTakenInMs });
  }

  return res.json({ ...buildAlert(match, text), engine });
});

/* ---------------- live Bright Data ingestion ----------------
   Each /ingest pulls the next fresh scam-alert source, scrapes it live through
   Bright Data's direct API, extracts a pattern from the real page text, and
   adds it to the Moss index incrementally (addDocs) — the "learns a new scam
   live" demo moment. The seed corpus is the safety net if a live fetch fails. */
const INGEST_QUEUE = [
  {
    url: "https://www.aarp.org/money/scams-fraud/bank-impersonation-fake-text-messages-emails-calls/",
    category: "bank_impersonation",
    subtype: "Bank impersonation call/text",
    source: "aarp",
  },
  {
    url: "https://www.aarp.org/money/scams-fraud/social-security/",
    category: "social_security",
    subtype: "Social Security impersonation",
    source: "aarp",
  },
];
let ingestPtr = 0;

app.post("/ingest", async (req, res) => {
  const src = req.body?.url ? req.body : INGEST_QUEUE[ingestPtr];
  if (!src) {
    return res.json({ added: 0, exhausted: true, total: patterns.length });
  }
  try {
    const md = await fetchMarkdown(src.url);
    const newPatterns = extractPatterns(md, src);
    if (newPatterns.length === 0) {
      return res.status(422).json({ error: "No pattern could be extracted from that page." });
    }
    for (const p of newPatterns) {
      patterns.push(p);
      patternById.set(p.id, p);
    }
    riskTerms = buildRiskTerms(patterns);

    let indexed = false;
    if (mossReady) {
      try {
        await addDocs(newPatterns);
        indexed = true;
      } catch (err) {
        console.warn("/ingest: addDocs failed:", err.message);
      }
    }
    if (!req.body?.url) ingestPtr++;

    res.json({
      added: newPatterns.length,
      indexed,
      total: patterns.length,
      patterns: newPatterns.map((p) => ({
        category: p.category,
        subtype: p.subtype,
        source: p.source,
        source_url: p.source_url,
        pattern_text: p.pattern_text,
      })),
    });
  } catch (err) {
    console.error("/ingest failed:", err.message);
    res.status(502).json({ error: `Live scrape failed: ${err.message}` });
  }
});

// Coverage panel data.
app.get("/stats", (_req, res) => {
  const categories = [...new Set(patterns.map((p) => p.category))];
  const sources = [...new Set(patterns.map((p) => p.source))];
  res.json({
    patternCount: patterns.length,
    categoryCount: categories.length,
    categories,
    sources,
    mossReady,
  });
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, patterns: patterns.length, mossReady });
});

// TEMP diagnostic — remove once the Moss native-binding deploy issue is resolved.
app.get("/diag", async (_req, res) => {
  const { readdirSync, statSync } = await import("fs");
  const { createRequire } = await import("module");
  const require = createRequire(import.meta.url);

  const scopeDir = join(__dirname, "node_modules", "@moss-dev");
  let entries = [];
  try {
    entries = readdirSync(scopeDir).map((name) => {
      const dir = join(scopeDir, name);
      let files = [];
      try {
        files = readdirSync(dir).map((f) => {
          try {
            const st = statSync(join(dir, f));
            return `${f} (${st.size} bytes)`;
          } catch {
            return f;
          }
        });
      } catch {}
      return { name, files };
    });
  } catch (err) {
    entries = [`error reading ${scopeDir}: ${err.message}`];
  }

  // Bypass moss-core's own try/catch-everything wrapper AND the package
  // "exports" restriction by dlopen-ing the .node file via its ABSOLUTE path.
  // This surfaces the REAL underlying error (e.g. a GLIBC version mismatch)
  // instead of moss-core's generic "Cannot find native binding" message.
  const bindingCandidates = [
    join(scopeDir, "moss-core", "js-binding.linux-x64-gnu.node"),
    join(scopeDir, "moss-core-linux-x64-gnu", "js-binding.linux-x64-gnu.node"),
  ];
  const directRequireResults = {};
  for (const candidate of bindingCandidates) {
    try {
      require(candidate);
      directRequireResults[candidate] = "OK";
    } catch (err) {
      directRequireResults[candidate] = err.message;
    }
  }

  res.json({
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.version,
    moss_dev_scope: entries,
    directRequireResults,
  });
});

app.listen(PORT, async () => {
  console.log(`Guardline backend listening on http://localhost:${PORT}`);
  console.log(`Loaded ${patterns.length} scam patterns across ${new Set(patterns.map((p) => p.category)).size} categories`);
  try {
    const count = await indexPatterns(patterns);
    mossReady = true;
    console.log(`Moss index loaded (${count} documents) — using real semantic matching`);
  } catch (err) {
    console.warn(`Moss not ready (${err.message}) — using keyword stub matcher until configured`);
  }
});
