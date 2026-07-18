/**
 * Real Moss client for Guardline, per docs.moss.dev/docs/start/quickstart.
 *
 * Confirmed response shape from a live query (2026-07-18):
 *   { docs: [{ id, text, score, metadata }], query, indexName, timeTakenInMs }
 *
 * Design: Moss is the semantic matcher and returns the matched pattern's id +
 * score. The server owns the full pattern records (actions, real_fact, etc.)
 * and joins on id — so complex fields never have to live in Moss metadata, and
 * live-ingested patterns work the same way as seed ones.
 */
// Dynamically imported (not a top-level import) so that if the native binding
// fails to load on a given machine, it surfaces as a rejected promise inside
// indexPatterns()'s try/catch in server.js instead of crashing the process
// before the stub fallback can kick in.
// Bump the version suffix if the seed corpus changes and you want a clean
// rebuild on the next deploy.
const INDEX_NAME = "guardline-scam-patterns-v1";

let client = null;
let indexLoaded = false;

async function getClient() {
  if (!client) {
    const projectId = process.env.MOSS_PROJECT_ID;
    const projectKey = process.env.MOSS_PROJECT_KEY;
    if (!projectId || !projectKey) {
      throw new Error("MOSS_PROJECT_ID / MOSS_PROJECT_KEY not set — copy backend/.env.example to backend/.env and fill in");
    }
    const { MossClient } = await import("@moss-dev/moss");
    client = new MossClient(projectId, projectKey);
  }
  return client;
}

// Build the embedding text for one pattern: the described tactic plus example
// phrases, so the index matches on meaning rather than exact wording.
function patternToDoc(p) {
  return {
    id: p.id,
    text: [p.pattern_text, ...(p.example_phrases || [])].join(" \n "),
    metadata: { category: p.category },
  };
}

/**
 * (Re)build and load the Moss index from the full pattern set.
 * @param {Array<object>} patterns
 * @returns {Promise<number>} number of documents indexed
 */
export async function indexPatterns(patterns) {
  const documents = patterns.map(patternToDoc);
  const c = await getClient();
  // Create the index, or — on a redeploy/restart where it already exists —
  // load the existing one instead of crashing.
  try {
    await c.createIndex(INDEX_NAME, documents, { modelId: "moss-minilm" });
  } catch (err) {
    console.warn(`createIndex skipped (${err.message}); loading existing index`);
  }
  await c.loadIndex(INDEX_NAME);
  indexLoaded = true;
  return documents.length;
}

export function isIndexLoaded() {
  return indexLoaded;
}

/**
 * Incrementally add patterns to the loaded index (no full rebuild).
 * Used by live Bright Data ingestion so the "update threat library" button
 * is fast. Falls back to a message if the index isn't loaded yet.
 * @param {Array<object>} patterns
 * @returns {Promise<number>} number of documents added
 */
export async function addDocs(patterns) {
  if (!indexLoaded) throw new Error("Moss index not loaded");
  const documents = patterns.map(patternToDoc);
  const c = await getClient();
  await c.addDocs(INDEX_NAME, documents);
  return documents.length;
}

/**
 * Semantic-match live transcript text against the index.
 * @param {string} text
 * @returns {Promise<{matched:boolean, id?:string, score?:number, timeTakenInMs?:number}>}
 */
export async function queryPattern(text, { topK = 1, threshold = 0.5 } = {}) {
  if (!indexLoaded) {
    throw new Error("Moss index not loaded — indexPatterns() must run at startup first");
  }

  const c = await getClient();
  const response = await c.query(INDEX_NAME, text, { topK });
  const docs = response?.docs ?? [];
  const timeTakenInMs = response?.timeTakenInMs;

  if (docs.length === 0) return { matched: false, timeTakenInMs };

  const top = docs[0];
  const score = top.score ?? 0;
  if (score < threshold) return { matched: false, score, timeTakenInMs };

  return { matched: true, id: top.id, score, timeTakenInMs };
}
