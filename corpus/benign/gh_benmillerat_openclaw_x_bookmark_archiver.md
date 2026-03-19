---
name: x-bookmark-archiver
version: 1.1.0
description: >
  Archive X/Twitter bookmarks as enriched Markdown notes with AI summaries.
  Use when the user asks to sync bookmarks, archive tweets, or pull X bookmarks into Obsidian.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: benmillerat/openclaw-x-bookmark-archiver
# corpus-url: https://github.com/benmillerat/openclaw-x-bookmark-archiver/blob/2e5946c25b55398d053a95246ec638a49e989edd/SKILL.md
# corpus-round: 2026-03-19
# corpus-format: markdown_fm
---

# X Bookmark Archiver

Archive X/Twitter bookmarks into enriched Markdown notes with AI-generated summaries, smart tagging, and article extraction.

## How It Works

This is a two-part skill:

1. **`scripts/sync.py`** — handles the mechanical work: fetches bookmarks from the X API, manages sync state, extracts articles, writes note files
2. **You (the agent)** — handle the intelligence: write interpretive summaries, pick relevant tags, assess relevance, enrich link context

When run standalone (e.g., via cron), `sync.py` uses built-in heuristics for summaries and tags. When run as an OpenClaw skill, **you do the enrichment** — which produces significantly better notes.

## Setup

See `README.md` for full setup instructions. Quick version:

1. Install `xurl`: `npm install -g @xdevplatform/xurl`
2. Register your X Developer app and authenticate OAuth2
3. Copy `config.example.json` → `config.json` and fill in your values
4. Dry-run: `python3 scripts/sync.py --config ./config.json --dry-run`

## Agent Workflow

When asked to archive or sync X bookmarks:

### Step 1: Fetch new bookmarks

Run the sync script with `--fetch-only` if available, or check the sync state and use `xurl` directly:

```bash
python3 scripts/sync.py --config /path/to/config.json --dry-run --verbose
```

Or fetch directly via xurl:

```bash
xurl --auth oauth2 --app {app_name} "/2/users/{user_id}/bookmarks?tweet.fields=created_at,text,author_id,entities,attachments,article&expansions=author_id&user.fields=username,name,description&max_results=100"
```

### Step 2: For each new bookmark, enrich it

For every bookmark not already archived:

#### a. Extract external URLs
- Skip `t.co` shortlinks — use expanded URLs from `entities.urls`
- Skip `x.com`/`twitter.com` links **except** X Articles (`x.com/i/article/...`)

#### b. Fetch link context
- For each external URL, try to fetch readable content (keep it quick, skip on failure)
- If fetch succeeds: use the content for both Summary and Link sections
- If fetch fails: still create the note, summarize from tweet text alone
- For X Articles: check `article.plain_text` from the API first, then try `x-tweet-fetcher`, then HTML fallback

#### c. Write a one-sentence summary
**Critical rules:**
- **Never copy or truncate the tweet text.** Write your own interpretation.
- For tweets with a fetched URL: summarize what the linked content is about
- For pure opinion/announcement tweets: distill the core point in your own words
- For X Articles where fetch failed: use article title + author to infer what it covers
- For short reply tweets with little standalone value: "Reply tweet — [brief context]"
- Always decode HTML entities: `&amp;` → `&`, `&lt;` → `<`, `&gt;` → `>`

#### d. Pick tags from the vocabulary
Choose 1–3 topical tags from the configured `tags_vocabulary`. Rules:
- **Always include `x-bookmarks`** as the base tag
- Tags must be Obsidian-safe: lowercase, hyphens/underscores only
- **Never leave tags empty**
- Be specific — `mcp` is better than `ai-agents` when the tweet is about MCP
- When in doubt, use `productivity` as fallback

#### e. Set relevance
- `try-this` — actionable tool, pattern, or workflow you could use now
- `reference` — good context to have, worth knowing
- `idea` — inspiration, might be relevant someday

### Step 3: Write the note

Each note follows this exact format:

```markdown
---
author: "@{username}"
date: {YYYY-MM-DD}
tags: [{comma-separated tags}]
relevance: {try-this|reference|idea}
tweet_id: "{id}"
url: https://x.com/{username}/status/{id}
source: x-bookmark
---

> {tweet text, blockquoted, t.co links removed, HTML entities decoded}

🔗 {expanded_url}

**Summary:** {your one-sentence interpretation}

**Link:** {2–3 sentences about what the linked page covers — ONLY if fetch succeeded}

[View on X](https://x.com/{username}/status/{id})
```

For X Articles, add these frontmatter fields and sections:

```yaml
article_title: "{title}"
article_url: https://x.com/i/article/{id}
article_extracted: true
```

```markdown
## Summary (Librarian)

**TL;DR:** {one sentence}

**Key takeaways:**
- {4–8 specific, concrete bullets}

**Actionables (if any):**
- {0–3 actionable bullets}

## Article (full text)

{full extracted article text}
```

### Step 4: Update sync state

After all notes are written, update the sync state file with the newest bookmark ID and current timestamp.

### Filename convention

`Compact Description - Author Name.md`
- "Compact Description" = meaningful title, title case, ≤60 chars
- Author = display name (not @username) if known
- Deduplicate with (2), (3) if needed

## Using the Helper Script

For the mechanical parts, the script handles everything:

```bash
# Full automated run (heuristic summaries + tags)
python3 scripts/sync.py --config ./config.json

# Dry run (check what would be archived)
python3 scripts/sync.py --config ./config.json --dry-run

# Verbose (debug logging)
python3 scripts/sync.py --config ./config.json --verbose
```

The script produces working notes on its own using heuristics. But your AI-generated summaries and tag choices will always be better.

## OAuth2 Reminder

Tokens expire every 2 hours. If you see `401` errors:

```bash
xurl auth oauth2 --app {app_name}
```

Always pass `--app` explicitly.

## Config Reference

| Key | Required | Description |
|-----|----------|-------------|
| `user_id` | Yes | X user ID |
| `app_name` | Yes | xurl app name (must match `--app` flag) |
| `output_dir` | Yes | Where Markdown notes are written |
| `sync_state_path` | Yes | JSON file for sync state |
| `tags_vocabulary` | No | Allowed tags (has sensible defaults) |
| `max_results` | No | Bookmarks per API page, 1–100 (default: 100) |
| `x_tweet_fetcher_path` | No | Path to x-tweet-fetcher if installed non-standard |