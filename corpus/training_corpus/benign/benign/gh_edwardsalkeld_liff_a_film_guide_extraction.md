---
name: film-guide-extraction
description: Extract structured film listings from LIFF guide PDFs into per-film JSON text files and maintain a resumable TODO list. Use when processing multi-page festival guide PDFs and tracking progress across sessions.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: EdwardSalkeld/liff-archive
# corpus-url: https://github.com/EdwardSalkeld/liff-archive/blob/c0b3c9e8a79980416bd747b951c9fdf9c1b62008/extraction-skill.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# Film Guide Extraction

## Overview

Extract film listings from PDF pages, write one JSON file per film into `films/`, and update `TODO.md` so the work can resume across sessions.

## Workflow

1. Ensure `TODO.md` exists and lists all `page-XX.pdf` files with checkboxes.
2. For each page, run `pdftotext -layout` first; if the output is garbled or missing, retry with `pdftotext -raw`.
3. Ignore non-listing content (ads, schedules, index, section intros). Mark those pages as no listings.
4. For each film listing, write a JSON file in `films/` using filename pattern `page-XX-title.json`.
5. Update `TODO.md` after finishing each page (include notes like “no films” or “skipped X”).

## Output Fields

Prefer consistent keys:

- `title`, `page`, `section`, optional `program`
- `venue_screenings`: array of `{ venue, date_text, time }`
- `directors`: array of names
- `countries`: array
- `year`, `runtime_minutes`
- `languages`: array, `subtitles` as string when present
- `certification`, `notes`, `synopsis` as needed

## Normalization Rules

- Convert `director` to `directors` list.
- Use `languages` list (merge `language`/`additional_language` into it).
- Keep ASCII-only output; replace typographic quotes with `'` or `\"`.
- Preserve short notes like “Free screening” in `notes`.