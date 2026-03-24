---
name: mila-paperoni-readonly
description: Query the Mila Paperoni publication database via REST API. This skill should be used when the user wants to search for papers by a specific Mila researcher, find all publications from an author, look up papers by title keyword, filter papers by conference or journal, see which venues Mila publishes to most, retrieve publication statistics, or perform any read-only analysis of Mila's research output using the Paperoni API.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: gyom/paperoni-claude-skill
# corpus-url: https://github.com/gyom/paperoni-claude-skill/blob/2f4baf7559ec93526010f6a899569e021c9c35bc/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# Paperoni — Mila Publication Database

Use this skill to query the Paperoni REST API for any read-only operation on Mila's publication record: researcher lookups, title searches, venue filters, publication statistics, and more.

## Authentication

The API requires a Bearer token in `PAPERONI_API_KEY`. Claude Code loads it automatically from whichever source the user configured (shell environment or `~/.claude/settings.json`). See the README for setup instructions.

**Critical:** Use Python `urllib` for all HTTP requests — do NOT use `curl`. Curl silently drops this token format's `Authorization` header, returning a 401 "Malformed authorization" error.

## Base URL

```
https://paperoni-web-503388805777.northamerica-northeast1.run.app
```

> Temporary fallback — the canonical URL `https://paperoni.mila.quebec` has a deployment issue. Update this skill when it is restored.

---

## Workflows

### 1 — Search papers (author / title / venue / institution)

Use `scripts/search_papers.py` for any query that returns a list of papers.

```bash
# All papers by a researcher
python3 .claude/skills/mila-paperoni-readonly/scripts/search_papers.py --author "Yoshua Bengio"

# Researcher's papers at a specific conference
python3 .claude/skills/mila-paperoni-readonly/scripts/search_papers.py --author "Aaron Courville" --venue "NeurIPS"

# Title keyword search
python3 .claude/skills/mila-paperoni-readonly/scripts/search_papers.py --title "diffusion model"

# Papers at a venue in a date range
python3 .claude/skills/mila-paperoni-readonly/scripts/search_papers.py --venue "ICLR" --start-date 2023-01-01

# All papers from Mila in 2024
python3 .claude/skills/mila-paperoni-readonly/scripts/search_papers.py --institution "Mila" --start-date 2024-01-01 --limit 0

# Look up a single paper by its Paperoni ID
python3 .claude/skills/mila-paperoni-readonly/scripts/search_papers.py --paper-id 69a8a6dab082dabfbcbf18de

# Papers added to the database in the last 7 days
python3 .claude/skills/mila-paperoni-readonly/scripts/search_papers.py --recent 7

# Output as JSON for further processing
python3 .claude/skills/mila-paperoni-readonly/scripts/search_papers.py --author "Hugo Larochelle" --json
```

All filters are combinable. `--limit 0` fetches all results (paginates automatically).
Full argument reference: `python3 .claude/skills/mila-paperoni-readonly/scripts/search_papers.py --help`

### 2 — Top publication venues (conference/journal statistics)

Use `scripts/fetch_venues.py` to rank all venues by paper count, with name normalisation.

```bash
# Top venues over the last 3 years (default)
python3 .claude/skills/mila-paperoni-readonly/scripts/fetch_venues.py

# Custom date range, show top 20
python3 .claude/skills/mila-paperoni-readonly/scripts/fetch_venues.py --start-date 2024-01-01 --top 20

# Show unrecognized venue names (useful for improving normalization)
python3 .claude/skills/mila-paperoni-readonly/scripts/fetch_venues.py --raw
```

The script normalises ~35 venue name variants to canonical names (e.g. `NeurIPS.cc/2025/Conference` → `NeurIPS`) and separates peer-reviewed venues from preprint servers.

### 3 — Ad-hoc API calls

For anything not covered by the scripts, call the API directly using this pattern:

```python
import urllib.request, urllib.parse, os, json

key = os.environ['PAPERONI_API_KEY']
BASE = 'https://paperoni-web-503388805777.northamerica-northeast1.run.app'

def api_get(path, params=None):
    url = BASE + path
    if params:
        url += '?' + urllib.parse.urlencode([(k, v) for k, v in params.items() if v is not None])
    req = urllib.request.Request(url, headers={'Authorization': f'Bearer {key}', 'accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())
```

See `references/api.md` for all available read-only endpoints and their parameters.

---

## Output Guidelines

- **Paper lists:** title in bold, authors in italics, venue + date, abstract snippet, DOI/arXiv link
- **Venue rankings:** ranked markdown table, preprints separated from peer-reviewed venues
- **Single paper:** full detail — title, all authors with affiliations, all releases, abstract, all links
- Always note the total result count and any active filters in the header

## Caveats

- A paper with multiple releases (e.g. arXiv preprint + NeurIPS proceedings) counts separately for each venue in statistics, but all releases are shown when displaying the paper itself
- Withdrawn submissions are excluded from venue counts
- Author name matching is a substring search — "Bengio" matches all Bengios; be specific if needed
- ~10% counting variance is acceptable for venue statistics (duplicate release entries exist in the data)