/**
 * Bright Data direct API client + scam-page → pattern extractor.
 *
 * The running app scrapes live through Bright Data's direct HTTP API using a
 * Web Unlocker zone (default `mcp_unlocker`) and the account API token.
 *
 * POST https://api.brightdata.com/request
 *   Authorization: Bearer <API_TOKEN>
 *   { zone, url, format:"raw", data_format:"markdown" }
 */

const BRIGHTDATA_ENDPOINT = "https://api.brightdata.com/request";
const ZONE = process.env.BRIGHTDATA_ZONE || "mcp_unlocker";

/** Fetch a URL through Bright Data and return it as markdown text. */
export async function fetchMarkdown(url) {
  const token = process.env.BRIGHTDATA_API_TOKEN;
  if (!token) throw new Error("BRIGHTDATA_API_TOKEN not set");

  const res = await fetch(BRIGHTDATA_ENDPOINT, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ zone: ZONE, url, format: "raw", data_format: "markdown" }),
  });

  if (!res.ok) {
    throw new Error(`Bright Data ${res.status}: ${(await res.text()).slice(0, 200)}`);
  }
  const text = await res.text();
  if (!text || text.trim().length < 200) {
    throw new Error("Bright Data returned little/no content (page may be a JS SPA)");
  }
  return text;
}

/* -------- extraction: scam-alert page → pattern documents --------
   AARP / BBB scam articles share a structure: an intro describing the scam,
   a "how it works" section, and a "how to protect yourself" / "tips" section.
   We segment on the page's real markdown headings and pull the actual prose,
   so the ingested pattern is genuinely derived from the page and stays sourced. */

// markdown link/formatting stripper
function clean(s) {
  return s
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1") // [text](url) -> text
    .replace(/[*_`#>]/g, "")
    .replace(/\\([.\-_*])/g, "$1")
    .replace(/\s+/g, " ")
    .trim();
}

const isHeading = (l) => /^#{1,6}\s/.test(l.trim());

// Sidebar / CTA / ad / caption noise that appears inside the article body.
const SKIP_RE =
  /(have you seen this scam|article continues|report a scam|sign up|get watchdog|watchdog alerts|subscribe|see all newsletters|privacy hub|generic-video|unlock access|already a member|benefits recommended|members only|en español|cartoon of|megaphone|logo|newsletter|advertisement)/i;

// Is this a line of real prose (not TOC, byline, image, caption, nav)?
function isProse(l) {
  const c = clean(l);
  if (c.length < 25) return false;
  if (l.includes("•")) return false; // "In this story" TOC line
  if (/^!/.test(l.trim())) return false; // image
  if (/^by\s+[A-Z]/.test(c) || /^updated\s|^published\s/i.test(c)) return false; // byline/date
  if (SKIP_RE.test(c)) return false;
  return true;
}

function sentences(text) {
  return clean(text)
    .split(/(?<=[.!?])\s+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 25 && s.length < 320);
}

// scraped pages sometimes contain letter-spaced text ("l e g i t i m a t e"),
// which shows up as many isolated single characters — reject those.
function looksSpaced(s) {
  return (s.match(/\b\w\s/g) || []).length > 6;
}

// a usable action is a real sentence (ends in punctuation), not a nav/related
// -article title, and not a spacing artifact.
function isAction(s) {
  return s && s.length > 20 && s.length < 200 && /[.!?]$/.test(s) && !looksSpaced(s);
}

/**
 * Extract a pattern document from a scraped scam-alert page.
 * @param {string} markdown
 * @param {{url:string, category:string, subtype:string, source:string}} meta
 * @returns {Array<object>} pattern docs (same schema as scam-patterns.json)
 */
export function extractPatterns(markdown, meta) {
  const all = markdown.split("\n").map((l) => l.replace(/\s+$/, "")).filter((l) => l.trim());

  const headingIdx = (kws) =>
    all.findIndex((l) => isHeading(l) && kws.some((k) => clean(l).toLowerCase().includes(k)));

  // body start: after the intro / "how it works" heading, else first long paragraph
  let start = headingIdx(["in this story", "how the scam works", "how it works", "how bank", "how the"]);
  start = start >= 0 ? start + 1 : all.findIndex((l) => isProse(l) && clean(l).length > 120);
  if (start < 0) return [];

  // body end: footer markers
  const endKws = ["aarp is a nonprofit", "still need assistance", "contact your local bbb", "more on", "report scams to bbb", "benefits recommended"];
  const endIdx = all.findIndex((l, i) => i > start && endKws.some((k) => clean(l).toLowerCase().includes(k)));
  const body = all.slice(start, endIdx > start ? endIdx : all.length);

  // split at the "how to protect / tips" heading
  const protectAt = body.findIndex(
    (l) => isHeading(l) && /(how to protect|protect yourself|tips to|how to avoid|what to do|how to know|how to spot)/i.test(clean(l))
  );
  const descLines = (protectAt > 0 ? body.slice(0, protectAt) : body).filter(isProse);
  const protectLines = (protectAt >= 0 ? body.slice(protectAt + 1) : []).filter(isProse);

  // pattern_text: how the scam works
  const pattern_text = sentences(descLines.join(" ")).slice(0, 3).join(" ");

  // actions: first real sentence of each protective paragraph (concise, sourced)
  const actions = protectLines
    .map((l) => sentences(l)[0])
    .filter(isAction)
    .slice(0, 4);

  // real_fact: a protective statement, preferring one with a clear safety cue
  const protectSents = protectLines.flatMap(sentences).filter((s) => !looksSpaced(s));
  const descSents = descLines.flatMap(sentences).filter((s) => !looksSpaced(s));
  const real_fact =
    protectSents.find((s) => /never|will not|do not|don't|hang up|contact your|call the/i.test(s)) ||
    descSents.find((s) => /never|will not|do not|don't|is a scam|are a scam/i.test(s)) ||
    actions[0] ||
    `Verify any such contact independently before acting (source: ${meta.source.toUpperCase()}).`;

  const CANDIDATE_TERMS = [
    "gift card", "prepaid", "wire", "wire transfer", "cryptocurrency", "bitcoin",
    "social security", "ssn", "bank account", "routing number", "password", "pin",
    "verify", "confirm", "suspended", "arrest", "warrant", "urgent", "immediately",
    "account", "refund", "overdue", "pay now", "remote access", "one-time code",
    "text message", "click", "link", "zelle", "venmo", "fraud department",
  ];
  const lower = (descLines.join(" ") + " " + protectLines.join(" ")).toLowerCase();
  const trigger_terms = CANDIDATE_TERMS.filter((t) => lower.includes(t));

  if (!pattern_text || pattern_text.length < 60) return [];

  return [
    {
      id: `${meta.category}-live-${Date.now().toString(36)}`,
      category: meta.category,
      subtype: meta.subtype,
      pattern_text,
      example_phrases: [],
      trigger_terms: trigger_terms.slice(0, 10),
      real_fact: real_fact.length > 260 ? real_fact.slice(0, 257) + "..." : real_fact,
      actions: actions.length ? actions : ["Hang up and verify independently through an official number"],
      severity: 2,
      source_url: meta.url,
      source: meta.source,
      live: true,
    },
  ];
}
