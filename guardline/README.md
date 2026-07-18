# Guardline

Real-time scam-call protection for elderly and vulnerable callers. A second device listens to ambient room audio, matches the conversation against a library of known scam patterns using **Moss** semantic search, and shows a silent, visual warning with concrete next steps — no synthesized voice, no call interception. The pattern library is built and grown live from real consumer-protection sources using **Bright Data**.

Built for Agent Hack Day with Moss @ Bright Data.

## Run locally

```bash
cd backend
npm install
# create backend/.env (see backend/.env.example):
#   MOSS_PROJECT_ID=...
#   MOSS_PROJECT_KEY=...
#   BRIGHTDATA_API_TOKEN=...
npm start
```

Open **http://localhost:3000** in **Google Chrome**.

- The backend serves the frontend on the same origin so the mic APIs work — `getUserMedia` / `AudioContext` (which power the audio-reactive orb) are blocked on `file://`.
- Live transcription uses the Web Speech API (`webkitSpeechRecognition`), which is Chrome-only. The **"Replay a sample scam call"** button works in any browser and needs no microphone.
- On startup the backend logs `Moss index loaded (N documents) — using real semantic matching`, or falls back to a keyword matcher if keys/native binding are missing — the app stays demoable either way.

## How it works

```
Chrome                                  Backend (Express, :3000)
  mic ─► Web Speech API ─► transcript ─► POST /check
  mic ─► AudioContext ─► orb amplitude        │
                                              ▼
                          lexical risk gate + Moss semantic query
                          against the scam-pattern index
                                              │
  alert card ◄── {category, subtype, real_fact, actions, source, ms} ◄┘

  "Update library" ─► POST /ingest ─► Bright Data scrapes a fresh scam page
                                   ─► extract pattern ─► Moss addDocs (live)
```

- **Moss** (`backend/moss-client.js`) — indexes the scam patterns and does the real-time semantic match; also supports incremental `addDocs` for live library growth.
- **Lexical risk gate** (`backend/server.js`) — a semantic hit must also contain real scam vocabulary before it alerts, so ordinary conversation never false-positives.
- **Bright Data** (`backend/brightdata.js`) — the running app scrapes real AARP/BBB scam-alert pages through Bright Data's direct API and extracts new patterns from the page text.

## API

| Route | Purpose |
|-------|---------|
| `POST /check` `{text}` | Semantic scam match → alert payload (category, subtype, real_fact, actions, severity, matched_terms, confidence, ms) |
| `GET /stats` | Coverage: pattern count, categories, sources |
| `POST /ingest` | Live-scrape the next source via Bright Data and add it to the index |
| `GET /health` | Liveness + Moss status |

## Two-device demo

- **Device A** ("the call") plays a realistic scam-call script out loud.
- **Device B** ("Guardline") runs this app in Chrome, listening to the room.

No telephony integration. Guardline hears ambient room audio on its own device, like "Hey Siri" — it never touches the phone line, never records, and never speaks.

## Deploy

Guardline is a **stateful long-running server** (it holds the Moss index in memory), so deploy it to a persistent-server host — **Render, Railway, Fly.io, or a VM** — not a serverless/static platform (Vercel/Netlify functions are stateless and short-lived, which breaks the in-memory index).

Settings:

- **Root directory:** `guardline/backend`
- **Build command:** `npm install`
- **Start command:** `npm start`
- **Runtime:** a standard **glibc** Node 18+ image (Debian/Ubuntu). Avoid Alpine/musl — the Moss native binding ships glibc builds.
- **Environment variables:** `MOSS_PROJECT_ID`, `MOSS_PROJECT_KEY`, `BRIGHTDATA_API_TOKEN` (never commit `.env`).
- **Health check:** allow a generous startup window (~30s) — the first boot builds the Moss index before serving.
- **HTTPS:** required for the live mic in Chrome (hosts provide this automatically). The replay demo works without it.

## Project layout

```
guardline/
  backend/    Express server, Moss client, Bright Data client
  data/       scam-patterns.json — real, sourced seed corpus
  frontend/   Plain HTML/CSS/JS — audio-reactive orb, no build step
```

See `EXPLANATION.md` (repo root) for a full walkthrough of the product, architecture, and how each sponsor's product is used.
