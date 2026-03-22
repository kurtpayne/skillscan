#!/usr/bin/env python3
"""
scrape_curated_repos.py — Fetch benign skills from curated GitHub skill repos.

Targets:
  - alirezarezvani/claude-skills (462 SKILL.md files)
  - daymade/claude-code-skills (44 SKILL.md files)
  - fal3/claude-skills-collection (9 SKILL.md files)

These are community-curated collections of legitimate agent skills, making
them ideal benign corpus sources with minimal filtering needed.

Usage:
  python scripts/scrape_curated_repos.py --target 50
  python scripts/scrape_curated_repos.py --target 50 --dry-run
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
CORPUS_BENIGN = REPO_ROOT / "corpus" / "benign"
ROUND = "2026-03-21"
SOURCE_TAG = "github-scrape-r4"

CURATED_REPOS = [
    "alirezarezvani/claude-skills",
    "daymade/claude-code-skills",
    "fal3/claude-skills-collection",
]

INJECTION_KEYWORDS = [
    r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\b",
    r"\boverride\s+(?:your\s+)?(?:instructions?|system|prompt|directive)\b",
    r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\b",
    r"\bforget\s+(?:all\s+)?(?:previous|prior|your)\b",
    r"\bact\s+as\s+(?:a\s+)?(?:DAN|jailbreak|unrestricted)\b",
    r"\bAGENT\s+DIRECTIVE\b",
    r"\bDEVELOPER\s+MODE\b",
    r"\bdo\s+anything\s+now\b",
    r"\bno\s+restrictions?\b",
    r"\bbypass\s+(?:safety|filter|restriction|guardrail)\b",
    r"\bexfiltrat\w+\b",
    r"\bexfil\b",
    r"\bsend\s+(?:all\s+)?(?:data|credentials?|password|token|secret)\b",
    r"\bsteal\s+(?:data|credentials?|password|token|secret)\b",
    r"\bhide\s+(?:this|your|the)\s+(?:instruction|directive|action|tool)\b",
    r"\bdo\s+not\s+(?:tell|inform|notify|reveal)\s+the\s+user\b",
    r"\bwithout\s+(?:telling|informing|notifying)\s+the\s+user\b",
    r"\bsilently\s+(?:execute|run|perform|send|delete)\b",
    r"\bskip\s+(?:confirmation|approval|review|human)\b",
    r"\bno\s+(?:confirmation|approval|human.in.the.loop)\b",
]
_INJECTION_RE = re.compile("|".join(INJECTION_KEYWORDS), re.IGNORECASE | re.MULTILINE)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("scrape_curated")


def gh_api_json(endpoint: str) -> dict | list | None:
    r = subprocess.run(["gh", "api", endpoint], capture_output=True, text=True)
    if r.returncode == 0:
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            return None
    if "rate limit" in r.stderr.lower():
        log.warning("Rate limited, waiting 60s...")
        time.sleep(60)
        return gh_api_json(endpoint)
    return None


def fetch_content(repo: str, path: str) -> str | None:
    data = gh_api_json(f"repos/{repo}/contents/{path}")
    if not data or not isinstance(data, dict):
        return None
    if data.get("encoding") == "base64":
        try:
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        except Exception:
            return None
    return data.get("content")


def is_quality(content: str) -> tuple[bool, str]:
    s = content.strip()
    if len(s) < 100:
        return False, f"too_short({len(s)})"
    if len(s) > 20_000:
        return False, f"too_long({len(s)})"
    m = _INJECTION_RE.search(s)
    if m:
        return False, f"injection({m.group()[:40]!r})"
    return True, "ok"


def content_hash(content: str) -> str:
    return hashlib.sha256(content.strip().encode()).hexdigest()


def make_filename(repo: str, path: str) -> str:
    owner, repo_name = repo.split("/", 1) if "/" in repo else ("unknown", repo)
    skill_stem = Path(path).stem.lower()
    owner_s = re.sub(r"[^a-z0-9]", "", owner.lower())[:12]
    repo_s = re.sub(r"[^a-z0-9]", "", repo_name.lower())[:12]
    skill_s = re.sub(r"[^a-z0-9_]", "_", skill_stem.lower())[:24].strip("_")
    return f"gh_{owner_s}_{repo_s}_{skill_s}.md"


def _extract_fm(content: str) -> tuple[dict, str]:
    if not content.startswith("---"):
        return {}, content
    end = content.find("\n---", 3)
    if end == -1:
        return {}, content
    fm_block = content[3:end].strip()
    body = content[end + 4:].strip()
    fm: dict = {}
    for line in fm_block.splitlines():
        if ":" in line and not line.strip().startswith("#"):
            k, _, v = line.partition(":")
            fm[k.strip()] = v.strip().strip('"').strip("'")
    return fm, body


def wrap_frontmatter(content: str, repo: str, path: str, url: str) -> str:
    existing_fm, body = _extract_fm(content)
    name = existing_fm.get("name") or Path(path).stem.replace("-", " ").replace("_", " ")
    description = existing_fm.get("description") or f"Community skill from {repo}"
    version = existing_fm.get("version") or "1.0"
    category = existing_fm.get("category") or "community"
    if len(description) > 120:
        description = description[:117] + "..."
    fm = f"""---
name: {name}
version: "{version}"
description: {description}
category: {category}
# corpus-label: benign
# corpus-source: {SOURCE_TAG}
# corpus-repo: {repo}
# corpus-url: {url}
# corpus-round: {ROUND}
# corpus-format: markdown_fm
---"""
    return fm + "\n" + (body if body else content)


def load_existing(corpus_dir: Path) -> tuple[set[str], set[str]]:
    hashes: set[str] = set()
    filenames: set[str] = set()
    for f in corpus_dir.glob("*.md"):
        filenames.add(f.name)
        try:
            hashes.add(content_hash(f.read_text(encoding="utf-8")))
        except Exception:
            pass
    return hashes, filenames


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Fetch benign skills from curated repos")
    parser.add_argument("--target", type=int, default=50)
    parser.add_argument("--output-dir", type=Path, default=CORPUS_BENIGN)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    existing_hashes, existing_filenames = load_existing(args.output_dir)
    initial_count = len(existing_filenames)
    log.info("Existing corpus: %d files", initial_count)

    all_fetched: list[dict] = []

    for repo in CURATED_REPOS:
        if len(all_fetched) >= args.target:
            break

        log.info("Scanning %s...", repo)
        tree_data = gh_api_json(f"repos/{repo}/git/trees/HEAD?recursive=1")
        if not tree_data or not isinstance(tree_data, dict):
            log.warning("  Could not fetch tree for %s", repo)
            continue

        skill_paths = [
            item["path"] for item in tree_data.get("tree", [])
            if re.search(r"SKILL\.md$", item["path"], re.IGNORECASE)
        ]
        log.info("  Found %d SKILL.md files", len(skill_paths))

        fetched_from_repo = 0
        skipped = 0
        errors = 0

        for path in skill_paths:
            if len(all_fetched) >= args.target:
                break

            filename = make_filename(repo, path)
            if filename in existing_filenames:
                skipped += 1
                continue

            content = fetch_content(repo, path)
            if not content:
                errors += 1
                continue

            ok, reason = is_quality(content)
            if not ok:
                log.debug("  SKIP %s: %s", path, reason)
                skipped += 1
                continue

            h = content_hash(content)
            if h in existing_hashes:
                skipped += 1
                continue

            url = f"https://github.com/{repo}/blob/HEAD/{path}"
            wrapped = wrap_frontmatter(content, repo, path, url)

            all_fetched.append({
                "filename": filename,
                "content": wrapped,
                "repo": repo,
                "path": path,
                "url": url,
            })
            existing_hashes.add(h)
            existing_filenames.add(filename)
            fetched_from_repo += 1

            if fetched_from_repo % 10 == 0:
                log.info("  Fetched %d from %s so far", fetched_from_repo, repo)

            time.sleep(0.3)

        log.info("  %s: fetched=%d skipped=%d errors=%d", repo, fetched_from_repo, skipped, errors)

    # Write files
    written = 0
    if not args.dry_run:
        for item in all_fetched:
            out_path = args.output_dir / item["filename"]
            out_path.write_text(item["content"], encoding="utf-8")
            written += 1

    print()
    print("=" * 60)
    print("CURATED REPO SCRAPE SUMMARY")
    print("=" * 60)
    print(f"  Initial corpus size : {initial_count}")
    print(f"  New skills fetched  : {len(all_fetched)}")
    print(f"  Written to disk     : {written}")
    print(f"  Final corpus size   : {initial_count + written}")
    if args.dry_run:
        print("  (DRY RUN — no files written)")
    print()
    if all_fetched:
        print("  Sample:")
        for item in all_fetched[:8]:
            print(f"    {item['filename']}")
        if len(all_fetched) > 8:
            print(f"    ... and {len(all_fetched) - 8} more")
    print("=" * 60)


if __name__ == "__main__":
    main()
