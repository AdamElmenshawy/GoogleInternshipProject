# Android Fuzzing, Crash Diagnosis & Security Bulletin Classifier Platform

A pipeline that fuzzes real Android libraries on a userdebug device, collects
genuine crash artifacts (tombstones + libFuzzer reproducers), minimizes them,
classifies them with Gemini against the official Android Security Bulletin
(ASB) reference set, and produces VRP-ready reports.

## Trust model

This pipeline is built to be **honest about what is real**:

- **No fabricated crashes.** The native runner only reports a crash when the
  fuzzer binary actually crashes. The old hardcoded sanitizer reports exist
  only as `--dry-run` fixtures and are marked `source: "simulation"`.
- **No simulation by default.** Default mode is `device`. Without a connected
  device the pipeline fails loudly. Simulation requires an explicit
  `--dry-run` / `FUZZER_MODE=simulation`, and simulated artifacts are never
  ingested as findings.
- **No heuristic fallback.** Analysis requires Gemini. If Gemini is
  unavailable or returns output that fails schema validation, the crash is
  queued for retry — never silently accepted, never silently discarded.
- **Reference set is strictly ASB.** Only records with `source === 'asb'`, a
  real bulletin ID (`ASB-A-*`, `PUB-A-*`, `CVE-*`), and a real (non-`Error`)
  summary may be used as reference examples. Fuzzer findings are never
  reference examples.
- **Status state machine.** Every crash passes
  `ingested → analyzed → pending_review → published`. Nothing in
  `pending_review` is a finding. Publishing requires a human action.

## Architecture

```
native_fuzzers/          Real AOSP libFuzzer harnesses (C++ + Android.bp)
  stagefright_hevc/      HEVC extractor fuzzer (libstagefright)
  binder_service/        SurfaceFlinger fuzzer (fuzzService)
  webp_image/            WebP decoder fuzzer (libwebp)

fuzzer/
  android_fuzzer.js       System/Intent fuzzer (device mode; dry-run fixtures)
  native_runner.js        Runs real libFuzzer binaries on device, parses output
  crash_collector.js      Tombstone pull + parse + crash minimization
  analyzer.js             Gemini classifier (structured output, no fallback)
  pipeline.js             End-to-end orchestrator
  vrp_reporter.js         VRP report generator (human-verification fields)

server.js                Express API (locked-down CORS, API-key auth, status machine)
SumPatches.js            ASB/OSV scraper (Gemini summaries)
scripts/                 One-off migrations (e.g. repair failed summaries)
asb-app/                 Next.js dashboard
```

## Requirements

- **A Linux AOSP build tree** to build the native fuzzers (the Android platform
  build is Linux-only). See `native_fuzzers/README.md` for Cuttlefish setup.
- **A connected userdebug device/emulator** for device-mode fuzzing.
- **`GEMINI_API_KEY`** for analysis (set in `.env` or the environment).
- **`INGEST_API_KEY`** for the API write endpoints (fail-closed if unset).

## Quick start

```bash
npm install

# Unit tests
npm test

# Dry-run pipeline (no device, no API key needed — simulated artifacts are
# dropped, not ingested)
npm run pipeline:dry-run

# Real pipeline (requires device + GEMINI_API_KEY)
npm run pipeline

# API server
npm run dev

# Frontend dashboard
npm run frontend
```

## API

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/vulnerabilities` | — | Published findings (filters: source, month, severity, component, status) |
| `GET /api/crashes` | — | Fuzzer crash records (review queue) |
| `GET /api/stats` | — | Dashboard metrics incl. status counts |
| `POST /api/crashes` | `x-api-key` | Ingest a crash (enters at `ingested`) |
| `POST /api/crashes/:id/publish` | `x-api-key` | Human approval → `published` |
| `POST /api/crashes/:id/reject` | `x-api-key` | Human decision → `rejected` |
| `POST /api/fuzzer/trigger` | `x-api-key` | Launch the pipeline (defaults to device mode) |

## VRP note

The VRP report generator (`fuzzer/vrp_reporter.js`) deliberately leaves
`securityImpact` and `affectedVersions` blank for human completion. Google's
VRP quality guidelines require a researcher-verified impact statement — an
AI-generated one will get the report flagged. AI output is a triage aid, never
a verbatim submission.
