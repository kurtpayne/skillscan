---
name: bilibili-up-digest
description: Use when the user wants to summarize tracked Bilibili creators into daily digests, creator index pages, or topic index pages inside the local Obsidian bilibili vault.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: WncFht/PulseDeck
# corpus-url: https://github.com/WncFht/PulseDeck/blob/8f7cbae1bae16d87311e37ae9052d0f52993ec1c/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# Bilibili UP Digest

Use this skill when the user wants Codex to maintain a tracked list of Bilibili creators and write their updates into `/Users/fanghaotian/Desktop/obsidian/bilibili`.

## One-Body Rule

- Each video has exactly one canonical note under `视频/`.
- Daily digest pages under `日报/` link to the video note and embed only `#日报摘要`.
- Dynamic posts live only in the daily page and do not get their own note.
- `UP主/` and `主题/` pages are navigation pages, not second copies of the summary body.

## Canonical Paths

- Vault root: `/Users/fanghaotian/Desktop/obsidian/bilibili`
- Config file: `/Users/fanghaotian/Desktop/obsidian/bilibili/配置/关注UP.yaml`
- Main workflow: `scripts/build_daily_digest.py`
- Index-only refresh: `scripts/rebuild_indexes.py`

## Main Workflow

Run the daily ingestion command:

```bash
uv run --with pyyaml --with bilibili-api-python --with curl_cffi python /Users/fanghaotian/.codex/skills/bilibili-up-digest/scripts/build_daily_digest.py \
  --vault-root /Users/fanghaotian/Desktop/obsidian/bilibili \
  --config /Users/fanghaotian/Desktop/obsidian/bilibili/配置/关注UP.yaml
```

Optional:

- Add `--date YYYY-MM-DD` to backfill or rerun a specific day.
- Add `--refresh-existing` if you want to rebuild already-existing canonical video notes instead of reusing them.
- Add `--refresh-bvid BV...` to refresh only specific canonical notes during a rerun without refreshing the whole day.
- Add `--bilinote-jobs N` to control `bilinote-cli` batch concurrency for missing notes.
- Add `--bilinote-batch-size N` to limit how many URLs are sent to a single `bilinote-cli` batch invocation.
- Add `--verbose` to stream per-stage progress and per-video actions to the terminal.

What it does:

- loads tracked creators from `关注UP.yaml`
- fetches tracked UP投稿 through `bilibili-api-python`
- ensures a local `RSSHub` service is available when dynamic collection is enabled
- backfills missing video publish time through the public Bilibili view API when rerunning past days
- reuses existing canonical video notes by default so reruns only generate missing notes unless `--refresh-existing` is set
- normalizes video and dynamic items
- batches missing video generation through local `bilinote-cli`
- writes or updates the daily digest page
- rebuilds touched creator and topic index pages

## Index-Only Refresh

Use this when the user wants to rebuild navigation pages from existing notes without fetching new content:

```bash
uv run --with pyyaml --with bilibili-api-python --with curl_cffi python /Users/fanghaotian/.codex/skills/bilibili-up-digest/scripts/rebuild_indexes.py \
  --vault-root /Users/fanghaotian/Desktop/obsidian/bilibili \
  --config /Users/fanghaotian/Desktop/obsidian/bilibili/配置/关注UP.yaml
```

## Notes

- `关注UP.yaml` remains the source of truth for tracked creators.
- `bilibili-api-python` is the default video discovery path.
- Dynamic collection uses a local Docker-backed `RSSHub` service when `rsshub.enabled: true`.
- `rsshub.cookie_file` should usually point at a local Bilibili cookie file rather than embedding a raw cookie string in YAML.
- If RSSHub startup or dynamic fetching fails, the digest still writes the daily page and records the issue under `告警与降级`.
- `bilinote-cli` is used for Markdown generation and batch concurrency.
- Video discovery is stability-first: the digest will reuse existing canonical notes for the target day and will try the public Bilibili video metadata API before giving up on a missing `published_at`.
- Existing video notes are reused by default. Use `--refresh-existing` to refresh them in place while keeping user-authored sections outside managed blocks.
- Use `--refresh-bvid` when you want a small live smoke test that still hits the `bilinote-cli` artifact path and refresh logic.
- Items missing `published_at` are skipped from the daily sections and recorded under `告警与降级`.
- Past-day reruns will avoid overwriting an existing daily page with an empty page when the new run only produced unresolved failures.
- Past-day reruns preserve the existing `## 动态更新` section when the rerun has dynamic-side warnings and cannot produce a trustworthy replacement.
- Daily pages split soft issues into `## 告警与降级` and hard failures into `## 失败与待补`.
- Duplicate canonical notes for the same `BVID` no longer abort the whole run; the digest picks a deterministic primary note and records a warning with the duplicate paths.
- When a batch actually invokes `bilinote-cli`, runtime artifacts are stored under `/Users/fanghaotian/Desktop/obsidian/bilibili/.bilibili-up-digest/runs/<target-day>/run-*/batch-*/` with `manifest.json`, `progress.jsonl`, `stdout.log`, and `stderr.log`.
- `progress.jsonl` now carries item-scoped heartbeats through long download/transcribe/summarize phases, so queued items are not mislabeled as started and stalled items are easier to localize.
- Batch failure reporting is item-scoped when artifacts exist; noisy shutdown warnings like `resource_tracker` should no longer collapse the whole batch into one generic outer error.
- Template shapes live in `references/templates.md`.