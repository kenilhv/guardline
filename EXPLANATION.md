# Guardline — Project Explanation

Real-time scam-call protection for elderly and vulnerable callers.

---

## 1. The problem

Phone scams are one of the largest and most under-addressed categories of fraud, and they disproportionately hit older adults. The FBI reported over **$390 million** lost to government-impersonation scams alone in a single recent year, up more than 60% year over year. The mechanics are always the same: a caller impersonates a trusted institution (the IRS, Medicare, a bank, a utility, a grandchild in trouble), manufactures **urgency** and **secrecy**, and pressures the victim into an irreversible payment — gift cards, wire transfers, prepaid cards.

The tragedy is that these scams are **well documented**. AARP, the BBB, and the FTC publish exactly what each scam sounds like and exactly what the truth is. But that knowledge is in articles nobody reads *during* the call — which is the only moment that matters.

**Guardline puts that knowledge into the call, in real time, silently.**

---

## 2. What Guardline is

A second device sits near the phone (on speaker) and listens to the room. As the call happens, Guardline:

1. Transcribes the conversation live.
2. Semantically matches each thing the caller says against a library of real, sourced scam patterns.
3. When it recognizes a scam, it shows a **silent visual alert** — the scam type, the **truth** that debunks it, **what to do right now**, and the **source** — while a live threat meter climbs.

It is deliberately **not** a voice assistant. It never speaks into the call, never records it, and never touches the phone line. It listens to ambient room audio on its own device — the same way "Hey Siri" listens — which also keeps it clear of call-recording consent laws.

### Who it's for

The realistic deployment is a family member setting it up for an aging parent: the parent keeps using their normal phone, and Guardline runs quietly on a nearby tablet, flagging danger the moment it appears.

---

## 3. End-to-end architecture

```
┌───────────────────────── Chrome (the "Guardline" device) ─────────────────────────┐
│                                                                                    │
│   microphone ──► Web Speech API ──────► live transcript segments                   │
│   microphone ──► Web Audio Analyser ──► amplitude ──► audio-reactive orb (canvas)  │
│                                             │                                      │
│                                   POST /check { text }                             │
└─────────────────────────────────────────────┼──────────────────────────────────────┘
                                               ▼
┌────────────────────────────── Backend (Node + Express) ────────────────────────────┐
│                                                                                    │
│   1. lexical risk gate   — does the text contain real scam vocabulary?             │
│   2. Moss semantic query — which scam pattern does this match, and how strongly?   │
│   3. join matched id ──►  full pattern record (real_fact, actions, severity…)      │
│                                                                                    │
│   POST /ingest ──► Bright Data scrapes a fresh scam-alert page ──► extract         │
│                    a new pattern ──► Moss.addDocs (grows the library live)          │
└─────────────────────────────────────────────┬──────────────────────────────────────┘
                                               ▼
                                   alert card + threat meter update
```

The backend also **serves the frontend** on the same origin. That is deliberate: browser microphone APIs (`getUserMedia`, `AudioContext`) are blocked on `file://` origins, so everything runs from `http://localhost:3000` (or the deployed HTTPS URL).

---

## 4. Components

### Backend (`guardline/backend/`)

- **`server.js`** — Express app. Endpoints:
  - `POST /check` — the detection pipeline (gate → Moss → join → alert payload).
  - `POST /ingest` — live Bright Data scrape that grows the library.
  - `GET /stats` — coverage panel data (pattern count, categories, sources).
  - `GET /health` — liveness + Moss status.
  - Also serves the static frontend.
- **`moss-client.js`** — wraps the Moss SDK: build/load the index, semantic `query`, incremental `addDocs`.
- **`brightdata.js`** — Bright Data direct-API client plus the scam-page → pattern extractor.

### Data (`guardline/data/scam-patterns.json`)

The seed corpus: **18 real scam sub-patterns** across 5 categories (IRS, tech-support, grandparent, Medicare, utility), each grounded in real AARP/BBB content. Every pattern carries:

| Field | Used for |
|-------|----------|
| `pattern_text` + `example_phrases` | the text Moss embeds and matches against |
| `trigger_terms` | phrases highlighted live in the transcript + risk-gate vocabulary |
| `real_fact` | the truth shown to debunk the scam |
| `actions` | concrete "what to do now" steps |
| `severity` | drives the call threat meter |
| `source` / `source_url` | attribution (AARP / BBB) |

### Frontend (`guardline/frontend/`)

Plain HTML/CSS/JS, no build step (so nothing can break at demo time):

- **Audio-reactive orb** — a canvas "Siri" orb driven by real microphone amplitude via an `AnalyserNode`. Calm teal while listening; the entire screen morphs to alarm-red on detection.
- **Threat meter** — accumulates severity across the call.
- **Live transcript** — with the exact triggering phrases highlighted.
- **Alert cards** — scam type, truth, "what to do now" steps, source, Moss latency + confidence.
- **Coverage panel** — live pattern count / categories / sources + "Update library".
- **Replay a sample scam call** — a mic-independent scripted call, so the core demo can never depend on live audio in a noisy room.

---

## 5. The detection pipeline (why it's built this way)

A naive version would just embed the transcript, find the nearest scam pattern, and alert. That fails in two ways, both of which Guardline handles:

**Problem 1 — small-corpus score inflation.** With a focused index, embedding similarity scores compress toward the top for almost *any* short English sentence ("traffic is bad today" scored 0.97 against a scam pattern in testing). A raw nearest-neighbor score is therefore **not** a reliable yes/no.

**Solution — a hybrid lexical + semantic gate.** A match only becomes an alert if the text *also* contains real scam vocabulary (`gift card`, `warrant`, `remote access`, `wire transfer`, …), assembled from every pattern's `trigger_terms` plus a base list. Moss decides *which* scam it is; the lexical gate decides *whether to alert at all*. In testing this took ordinary conversation to zero false positives while every paraphrased scam still matched its correct sub-type.

**Problem 2 — coarse categories.** "IRS scam" is really several distinct scripts (arrest threat, fake refund, gift-card demand, robocall callback). A single document per category can't distinguish them.

**Solution — sub-pattern chunking.** Each scam type is split into multiple focused documents, so a matched alert names the *specific* tactic and shows the *specific* truth and actions for it.

---

## 6. Sponsor products — what they are, and how Guardline uses them

The two capabilities Guardline needs — **understanding messy spoken language in real time** and **turning the open web's fraud knowledge into structured data** — map almost exactly onto the two sponsors. Below is an honest account of each product's full capability set and which parts Guardline actually exercises.

### 6a. Moss — real-time semantic search

**What it is.** Moss is a real-time semantic-search engine aimed at AI agents, voice AI, copilots, docs search, and on-device / edge apps — anywhere retrieval has to be both semantic *and* fast. Queries return in single-digit milliseconds.

**Full capability set (from the SDK and docs):**

| Capability | What it does | Guardline use |
|---|---|---|
| `createIndex` / `loadIndex` | Build and load a cloud-backed semantic index | ✅ Core — the scam-pattern library |
| `query(topK)` | Semantic nearest-neighbour search with scores | ✅ Core — every `/check` |
| `addDocs` | Incrementally add documents to a loaded index | ✅ Used by live `/ingest` (no full rebuild) |
| Document `metadata` | Attach structured fields to each doc | ✅ Lightly (category); Guardline joins richer records app-side |
| `deleteDocs` | Remove documents | ❌ Not needed — the library only grows |
| **`session()`** — local-first, in-process index | A short-term index that lives in memory with **zero cloud round-trip**, designed for live-call context (add transcript turns as they arrive, query locally) | ❌ **Not yet wired** — this is the single most natural next step (see §8). It would let Guardline reason about the *whole call so far* (escalation across turns), which is exactly what Moss built it for. |
| `createIndexFromFiles` | Server-side parse + embed of raw files | ❌ Not needed — patterns are already structured JSON |
| Auto-refresh + `cachePath` | On-device persistence and periodic cloud sync | ❌ Not needed for a server deployment |
| `moss-minilm` / `moss-mediumlm` | Small vs. medium embedding models | ✅ `moss-minilm` (enough for short phrases) |
| Metadata **filtering** at query time | Restrict search to a metadata subset | ❌ Deliberately unused — Guardline searches *all* patterns to *classify* the call, so filtering would work against the goal |
| Swift / on-device (iOS) SDK | Fully local embedding + query on a phone | ❌ Guardline is a browser + Node app, not native iOS |

**Why Moss is load-bearing, not decorative.** Scammers paraphrase endlessly — "there's a warrant for your arrest," "officers are being dispatched," "you'll be taken into custody over back taxes" are one pattern in three wordings. Keyword search misses paraphrase; Moss catches it. And it has to happen inside the natural pause after a sentence, so the millisecond latency is the point, not a nicety. Remove Moss and Guardline becomes a brittle keyword matcher.

### 6b. Bright Data — web data infrastructure

**What it is.** Bright Data is a web-data platform: proxy networks plus higher-level APIs that handle unblocking, CAPTCHA solving, JavaScript rendering, search, crawling, browser automation, and structured extraction — i.e. reliably turning arbitrary public web pages into usable data.

**Full capability set:**

| Capability | What it does | Guardline use |
|---|---|---|
| **Web Unlocker** (`POST /request`, `data_format:markdown`) | Fetch a page as a real browser would — proxies, fingerprints, CAPTCHA, JS render — and return clean markdown | ✅ Core — how the app scrapes AARP/BBB scam pages, at build time and live at runtime |
| SERP / `search_engine` (+ batch) | Programmatic search-engine results | ✅ Used during development to *discover* the source pages; the app hardcodes known-good sources at runtime for reliability |
| `scrape_batch` | Scrape many URLs at once | ✅ Used at build time to pull the initial corpus |
| MCP server (60+ tools) | Discover / search / scrape / extract / browser tools exposed to AI dev tools | ✅ Used during development to assemble the corpus (the deployed app uses the direct HTTP API, not MCP) |
| Scraping Browser / full browser automation | Drive a real browser for complex interactive flows | ❌ Not needed — scam-alert articles render fine through the Unlocker |
| Web Scraper API / managed datasets | Prebuilt structured extractors for specific sites, dataset delivery | ❌ Not used — Guardline does its own lightweight extraction |
| Structured-extraction endpoints | Server-side field extraction | ❌ Guardline extracts fields itself (see below) |
| Raw proxy network | Direct proxy access | ❌ Consumed indirectly through the Unlocker |

**How Guardline actually uses it.** Two moments:

1. **Build time** — discover and scrape the real FTC/AARP/BBB scam-alert pages that became the seed corpus. (Honest note: `consumer.ftc.gov` / `irs.gov` returned empty through the Unlocker's markdown mode — they're heavy JS SPAs — while AARP and BBB rendered cleanly, so the sourced facts come from AARP and BBB.)
2. **Run time** — the **"Update library"** button hits `/ingest`, which uses Bright Data's direct API to scrape a *fresh* scam-alert page live, runs a heading-aware extractor over the returned markdown to pull the real "how it works" prose and "how to protect yourself" steps, and adds the new pattern to Moss via `addDocs`. This is what lets Guardline **learn a brand-new scam type on stage** and start catching it seconds later.

**Why Bright Data is load-bearing, not decorative.** These sources are exactly the kind of pages a plain `fetch()` fails on — JS-rendered, bot-protected, inconsistent structure. Bright Data is what makes "the fraud knowledge of the open web, as live structured data" actually work. Remove it and Guardline is frozen to a hand-written static list.

**Honest scope note.** Guardline uses the *unblock-and-scrape* slice of Bright Data thoroughly and for real, but it does not exercise the heavier machinery (browser automation, managed structured-extraction datasets, large-scale crawling). The use is genuine and central to the product, not maximal across Bright Data's catalogue.

---

## 7. Design decisions & honest limitations

- **Listen-only, no TTS.** A voice that talks into a live call would tip off the scammer, talk over the conversation, and add failure points. Silent visual alerts are better on every axis.
- **Ambient audio, not call tapping.** Sidesteps two-party call-recording consent law by design — Guardline records its own room on its own device and does not retain the audio.
- **Web Speech API is Chrome-only** and struggles in very noisy rooms — which is precisely why the **mic-independent replay** exists as demo insurance.
- **Small corpus by design (for now).** 18 seed patterns + live growth, not thousands. The lexical gate compensates for small-corpus score inflation; the honest next step is a much larger ingested library.
- **Extraction is heuristic.** The live-ingest extractor is tuned to AARP/BBB article structure; a page with a very different layout may yield a rougher pattern. Seed patterns are hand-verified; live-ingested ones are clearly marked.

---

## 8. What's next

- **Moss live-call session index (`session()`).** Wire a per-call in-memory session index so Guardline reasons across the *whole* conversation, not just the latest sentence — detecting escalation (authority claim → urgency → payment demand) that no single line reveals. This is the most natural depth upgrade and is exactly what Moss's session API is built for.
- **Larger ingested library.** Use Bright Data to discover and ingest dozens of sources across many more scam categories.
- **Trusted-contact alerting.** Notify a family member the moment a high-severity scam is detected.

---

## 9. Demo in one paragraph

Open Guardline. It shows a calm listening orb and a live library ("18 scam patterns · AARP, BBB"). Press **Update library** — it scrapes a fresh scam type from AARP live via Bright Data and the count ticks up. Now press **Replay a sample scam call**: a scripted IRS call plays, the transcript streams in with danger words lighting up, the threat meter climbs to **High**, the whole screen turns red, and an alert card names the scam, states the truth ("the IRS initiates contact by mail… it will never demand gift-card payment or threaten arrest"), and tells the caller exactly what to do — matched by Moss in **0 ms**, sourced from AARP **via Bright Data**.
