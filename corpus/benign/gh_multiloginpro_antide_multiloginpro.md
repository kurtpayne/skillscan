---
name: multiloginpro
description: Operate a running MultiLoginPro instance through its local HTTP API (http://192.168.0.123:39633/api). Use this when you need to list/start/close profiles, drive browser tabs, inject cookies, or interact with page elements programmatically. All endpoints are POST requests with JSON bodies.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: MultiLoginPro/antidetect-browser-tools
# corpus-url: https://github.com/MultiLoginPro/antidetect-browser-tools/blob/2b5105b54f833aeda30b1e348280b0ce9e83ccca/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# MultiLoginPro API Skill

## Overview
This skill packages the official MultiLoginPro API doc so you can script the local controller without reopening the website every time. It covers the POST request envelopes, `searchElement` descriptors, profile lifecycle, and the dozens of `/browser/*` helpers (load URL, screenshot, cookies, element automation, etc.).

**Reference file:** [`references/api-endpoints.md`](references/api-endpoints.md) — full endpoint table plus parameter notes copied from https://multiloginpro.com/api.html (fetched 2026‑03‑02) with the POST requirement highlighted.

## Quick Start
1. **Ensure the API service is up:** Start MultiLoginPro and confirm the default base URL `http://192.168.0.123:39633/api` responds.
2. **Send POST requests with JSON bodies:** Every documented endpoint expects HTTP POST + JSON payload. Responses look like:
   ```json
   {"success":true,"result":{},"error":null,"browserNotFound":false}
   ```
3. **Sample curl template:**
   ```bash
   curl -X POST http://192.168.0.123:39633/api/profile/list \
     -H "Content-Type: application/json" \
     -d '{"type":1}'
   ```
4. **Use `browserId` vs `profileId` properly:** profile endpoints accept either identifier; browser endpoints always need `browserId` returned by `/profile/start`.

## Core Workflows

### 1. Manage profiles
1. `POST /environment/create` to create a new profile.
2. `POST /profile/list` with `{ "type": 0|1|2 }` to fetch profiles and pick `profileId`.
3. `POST /profile/start` to launch one → note the returned `browserId`, `httpDebugAddress`, `wsDebugAddress`.
4. Optional: `POST /profile/close` with either identifier when finished.

### 2. Drive a browser session
1. **Navigation**: `/browser/loadurl` (`browserId`, `url`, `newTab`, `timeout`).
2. **Tab control**: `/browser/switchtab` or `/browser/closetab` (match by URL or target last tab).
3. **Operate & keyboard**: `/browser/elementoperate` and `/browser/keystrokesemulation` supplement element-level actions.

### 3. Work with elements
1. Build a `searchElement` descriptor (`selector`, `isXPath`, `index`, iframe hints). Details live in the reference table.
2. Find and cache elements via `/browser/findelement`.
3. Act on them:
   - `/browser/setvalue`
   - `/browser/elementoperate`
   - `/browser/keystrokesemulation`
4. Scrape data:
   - `/browser/scrapeonetext` for single property (e.g., `.value`)
   - `/browser/scrapesometext` to collect arrays (and save under `saveVarName`)
   - `/browser/scrapespecialtext` for source/title/body/current URL

### 4. Cookie + state management
- `/browser/getcookie` (scope to one domain) vs `/browser/getallcookies` (entire jar).
- `/browser/setcookie` expects a **stringified** JSON array of DevTools-style cookie objects.
- `/browser/clearcookies` wipes everything before a run.

### 5. Visuals & debugging
- `/browser/getimage`: screenshot entire page or pass `elementScreenshot=true` with `searchElement` for targeted captures.
- `/browser/executejs`: run arbitrary JavaScript (`js` string). Use `inIframe` + `selectorForIframe` if the script must run inside nested contexts.

### 6. Wait loops & automation cadence
- `/browser/pageloadwait`: loop (count + sleep) until an element appears. Great for DOM readiness before interacting.
- Combine with `/browser/elementoperate` and `/browser/keystrokesemulation` to mimic user flows.

## searchElement Cheat Sheet
| Field | Notes |
| --- | --- |
| `parent` | Optional CSS selector to limit scope |
| `selector` | CSS or XPath text (set `isXPath=true` for XPath) |
| `index` | 0-based pick; use `-1` to target all matches |
| `searchAllIframe` | true = scan every iframe |
| `selectorForSearchIframe` | supply the iframe locator first, then search inside |
 
## Troubleshooting
- **`success: false`, `browserNotFound: true`** → stale `browserId`. Restart the profile.
- **Cookie payload errors** → remember to double-escape quotes or send via file (`curl --data @cookies.json`).
- **Element not found** → confirm `selector` and `index`, and whether the element lives inside an iframe.
- **Timeouts while waiting** → adjust `/browser/pageloadwait` `loop` × `sleep` values.

For parameter-by-parameter guidance and sample responses, open [`references/api-endpoints.md`](references/api-endpoints.md).