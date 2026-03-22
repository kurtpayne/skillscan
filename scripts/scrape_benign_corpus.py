#!/usr/bin/env python3
"""
scrape_benign_corpus.py — Gap #3: Benign Corpus Expansion
==========================================================

Scrapes real SKILL.md files from GitHub and the mattnigh/skills_collection
aggregator repo, quality-filters them, deduplicates, and writes them to
corpus/benign/ with standard YAML frontmatter.

Sources:
  1. mattnigh/skills_collection — 2400+ community-contributed SKILL.md files
     (already aggregated, easy to bulk-fetch)
  2. GitHub code search — filename:SKILL.md + keyword filters targeting
     Claude/Manus-style agent skills with legitimate tool use

Quality filters (reject if ANY of the following):
  - Content length < 100 chars or > 20 000 chars
  - Contains any injection/override keywords (hard reject)
  - No recognizable SKILL.md structure (no ## section or YAML frontmatter)
  - Duplicate content (SHA-256 of stripped content)
  - Already in corpus (filename dedup)

Output format:
  corpus/benign/gh_{owner}_{repo_short}_{skill_name}.md
  with YAML frontmatter:
    name, version, description, category,
    corpus-label: benign
    corpus-source: github-scrape-r4
    corpus-repo, corpus-url, corpus-round, corpus-format

Usage:
  # Dry run (show what would be fetched, no writes)
  python scripts/scrape_benign_corpus.py --dry-run

  # Fetch up to 80 new benign skills
  python scripts/scrape_benign_corpus.py --target 80

  # Fetch from skills_collection only
  python scripts/scrape_benign_corpus.py --source collection --target 60

  # Fetch from GitHub code search only
  python scripts/scrape_benign_corpus.py --source github --target 40
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent
CORPUS_BENIGN = REPO_ROOT / "corpus" / "benign"
ROUND = "2026-03-21"
SOURCE_TAG = "github-scrape-r4"

# Hard-reject keywords — any of these in the content → skip
INJECTION_KEYWORDS = [
    r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\b",
    r"\boverride\s+(?:your\s+)?(?:instructions?|system|prompt|directive)\b",
    r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\b",
    r"\bforget\s+(?:all\s+)?(?:previous|prior|your)\b",
    r"\bact\s+as\s+(?:a\s+)?(?:DAN|jailbreak|unrestricted)\b",
    r"\bAGENT\s+DIRECTIVE\b",
    r"\bDEVELOPER\s+MODE\b",
    r"\bDAN\s+MODE\b",
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

_INJECTION_RE = re.compile(
    "|".join(INJECTION_KEYWORDS),
    re.IGNORECASE | re.MULTILINE,
)

# Minimum structure markers — must have at least one of these
STRUCTURE_MARKERS = [
    r"^#{1,3}\s+\w",           # ## Section heading
    r"^---\s*$",               # YAML frontmatter delimiter
    r"^name\s*:",              # YAML name field
    r"^description\s*:",       # YAML description field
    r"^\*\*\w",                # Bold text (common in SKILL.md)
]
_STRUCTURE_RE = re.compile(
    "|".join(STRUCTURE_MARKERS),
    re.MULTILINE,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("scrape_benign")


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

def gh_api(endpoint: str, max_retries: int = 3) -> dict | list | None:
    """Call the GitHub API via gh CLI and return parsed JSON."""
    for attempt in range(1, max_retries + 1):
        result = subprocess.run(
            ["gh", "api", endpoint],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return None
        if "rate limit" in result.stderr.lower():
            wait = 60 * attempt
            log.warning("Rate limited. Waiting %ds...", wait)
            time.sleep(wait)
        elif attempt == max_retries:
            log.debug("API error for %s: %s", endpoint, result.stderr[:100])
            return None
        else:
            time.sleep(2)
    return None


def fetch_raw_content(repo: str, path: str, ref: str = "HEAD") -> str | None:
    """Fetch raw file content from GitHub."""
    # Use the contents API
    endpoint = f"repos/{repo}/contents/{path}"
    data = gh_api(endpoint)
    if not data or not isinstance(data, dict):
        return None
    if data.get("encoding") == "base64":
        import base64
        try:
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        except Exception:
            return None
    return data.get("content")


def search_code(query: str, per_page: int = 100) -> list[dict]:
    """Run a GitHub code search and return items."""
    result = subprocess.run(
        ["gh", "api", f"search/code?q={query}&per_page={per_page}",
         "--jq", ".items[] | {repo: .repository.full_name, path: .path}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return []
    items = []
    for line in result.stdout.strip().splitlines():
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return items


# ---------------------------------------------------------------------------
# Quality filter
# ---------------------------------------------------------------------------

def is_quality_skill(content: str) -> tuple[bool, str]:
    """
    Return (ok, reason) for a candidate skill file.
    ok=True means it passes quality filters.
    """
    stripped = content.strip()

    # Length check
    if len(stripped) < 100:
        return False, f"too_short({len(stripped)})"
    if len(stripped) > 20_000:
        return False, f"too_long({len(stripped)})"

    # Injection keyword check
    m = _INJECTION_RE.search(stripped)
    if m:
        return False, f"injection_keyword({m.group()[:40]!r})"

    # Structure check
    if not _STRUCTURE_RE.search(stripped):
        return False, "no_structure"

    return True, "ok"


def content_hash(content: str) -> str:
    """SHA-256 of stripped content for deduplication."""
    return hashlib.sha256(content.strip().encode()).hexdigest()


# ---------------------------------------------------------------------------
# Filename generation
# ---------------------------------------------------------------------------

def make_filename(repo: str, path: str) -> str:
    """
    Generate a corpus filename like gh_{owner}_{repo_short}_{skill_name}.md
    Mirrors the convention used in existing corpus files.
    """
    owner, repo_name = repo.split("/", 1) if "/" in repo else ("unknown", repo)
    skill_stem = Path(path).stem.lower()

    # Sanitize: keep only alphanumeric and underscore, max 20 chars each
    owner_s = re.sub(r"[^a-z0-9]", "", owner.lower())[:12]
    repo_s = re.sub(r"[^a-z0-9]", "", repo_name.lower())[:12]
    skill_s = re.sub(r"[^a-z0-9_]", "_", skill_stem.lower())[:24].strip("_")

    return f"gh_{owner_s}_{repo_s}_{skill_s}.md"


# ---------------------------------------------------------------------------
# YAML frontmatter injection
# ---------------------------------------------------------------------------

def _extract_existing_frontmatter(content: str) -> tuple[dict, str]:
    """
    Extract existing YAML frontmatter from content.
    Returns (frontmatter_dict, body_without_frontmatter).
    """
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


def wrap_with_frontmatter(
    content: str,
    repo: str,
    path: str,
    url: str,
) -> str:
    """
    Wrap content with standard corpus YAML frontmatter.
    Preserves any existing name/description from the file.
    """
    existing_fm, body = _extract_existing_frontmatter(content)

    name = existing_fm.get("name") or Path(path).stem.replace("-", " ").replace("_", " ")
    description = existing_fm.get("description") or f"Community skill from {repo}"
    version = existing_fm.get("version") or "1.0"
    category = existing_fm.get("category") or "community"

    # Truncate description if too long
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


# ---------------------------------------------------------------------------
# Source: mattnigh/skills_collection
# ---------------------------------------------------------------------------

def fetch_from_collection(
    target: int,
    existing_hashes: set[str],
    existing_filenames: set[str],
    dry_run: bool,
) -> list[dict]:
    """
    Fetch benign skills from mattnigh/skills_collection.
    Returns list of dicts: {filename, content, repo, path, url}
    """
    log.info("Fetching from mattnigh/skills_collection...")

    # Get the file list from the collection repo
    result = subprocess.run(
        ["gh", "api", "repos/mattnigh/skills_collection/git/trees/HEAD?recursive=1",
         "--jq", '.tree[] | select(.path | endswith("SKILL.md")) | {path: .path, sha: .sha}'],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log.error("Failed to list skills_collection: %s", result.stderr[:100])
        return []

    all_paths = []
    for line in result.stdout.strip().splitlines():
        try:
            all_paths.append(json.loads(line))
        except json.JSONDecodeError:
            pass

    log.info("  Found %d SKILL.md files in collection", len(all_paths))

    fetched = []
    skipped = 0
    errors = 0

    for item in all_paths:
        if len(fetched) >= target:
            break

        path = item["path"]

        # Extract original repo info from the collection path
        # Format: collection/{owner}__{repo}__{...}__SKILL.md
        # or: collection/{owner}__{repo}__claude__skills__{skill}__SKILL.md
        parts = path.replace("collection/", "").split("__")
        if len(parts) >= 2:
            orig_owner = parts[0]
            orig_repo = parts[1]
            orig_repo_full = f"{orig_owner}/{orig_repo}"
        else:
            orig_repo_full = "mattnigh/skills_collection"

        filename = make_filename(orig_repo_full, path)
        if filename in existing_filenames:
            skipped += 1
            continue

        content = fetch_raw_content("mattnigh/skills_collection", path)
        if not content:
            errors += 1
            continue

        ok, reason = is_quality_skill(content)
        if not ok:
            log.debug("  SKIP %s: %s", path, reason)
            skipped += 1
            continue

        h = content_hash(content)
        if h in existing_hashes:
            log.debug("  SKIP %s: duplicate content", path)
            skipped += 1
            continue

        url = f"https://github.com/mattnigh/skills_collection/blob/main/{path}"
        wrapped = wrap_with_frontmatter(content, orig_repo_full, path, url)

        fetched.append({
            "filename": filename,
            "content": wrapped,
            "repo": orig_repo_full,
            "path": path,
            "url": url,
        })
        existing_hashes.add(h)
        existing_filenames.add(filename)

        if len(fetched) % 10 == 0:
            log.info("  Fetched %d / %d target", len(fetched), target)

        # Be polite to the API
        time.sleep(0.3)

    log.info("  Collection: fetched=%d skipped=%d errors=%d", len(fetched), skipped, errors)
    return fetched


# ---------------------------------------------------------------------------
# Source: GitHub code search
# ---------------------------------------------------------------------------

def fetch_from_github_search(
    target: int,
    existing_hashes: set[str],
    existing_filenames: set[str],
    dry_run: bool,
) -> list[dict]:
    """
    Fetch benign skills from GitHub code search.
    Returns list of dicts: {filename, content, repo, path, url}
    """
    log.info("Fetching from GitHub code search...")

    # Multiple targeted queries to find legitimate agent skills
    queries = [
        "filename:SKILL.md+allowed-tools+description",
        "filename:SKILL.md+instructions+tools+path:.claude",
        "filename:SKILL.md+instructions+tools+path:skills",
        "filename:SKILL.md+## Overview+## Instructions",
        "filename:SKILL.md+## Steps+## Tools",
    ]

    all_candidates: list[dict] = []
    seen_repos: set[str] = set()

    for query in queries:
        if len(all_candidates) >= target * 3:  # gather 3x to account for filtering
            break
        items = search_code(query, per_page=100)
        for item in items:
            key = f"{item['repo']}:{item['path']}"
            if key not in seen_repos:
                seen_repos.add(key)
                all_candidates.append(item)
        time.sleep(2)  # respect search rate limit

    log.info("  Code search: %d unique candidates", len(all_candidates))

    fetched = []
    skipped = 0
    errors = 0

    # Exclude the skills_collection (handled separately) and known malicious repos
    EXCLUDE_REPOS = {
        "mattnigh/skills_collection",
        "kurtpayne/skillscan-security",
    }

    for item in all_candidates:
        if len(fetched) >= target:
            break

        repo = item["repo"]
        path = item["path"]

        if repo in EXCLUDE_REPOS:
            continue

        filename = make_filename(repo, path)
        if filename in existing_filenames:
            skipped += 1
            continue

        content = fetch_raw_content(repo, path)
        if not content:
            errors += 1
            continue

        ok, reason = is_quality_skill(content)
        if not ok:
            log.debug("  SKIP %s/%s: %s", repo, path, reason)
            skipped += 1
            continue

        h = content_hash(content)
        if h in existing_hashes:
            log.debug("  SKIP %s/%s: duplicate", repo, path)
            skipped += 1
            continue

        # Build GitHub URL
        url = f"https://github.com/{repo}/blob/HEAD/{path}"
        wrapped = wrap_with_frontmatter(content, repo, path, url)

        fetched.append({
            "filename": filename,
            "content": wrapped,
            "repo": repo,
            "path": path,
            "url": url,
        })
        existing_hashes.add(h)
        existing_filenames.add(filename)

        if len(fetched) % 10 == 0:
            log.info("  Fetched %d / %d target", len(fetched), target)

        time.sleep(0.5)

    log.info("  GitHub search: fetched=%d skipped=%d errors=%d", len(fetched), skipped, errors)
    return fetched


# ---------------------------------------------------------------------------
# Existing corpus loader (for dedup)
# ---------------------------------------------------------------------------

def load_existing_corpus(corpus_dir: Path) -> tuple[set[str], set[str]]:
    """
    Load existing corpus files to build dedup sets.
    Returns (content_hashes, filenames).
    """
    hashes: set[str] = set()
    filenames: set[str] = set()

    for f in corpus_dir.glob("*.md"):
        filenames.add(f.name)
        try:
            h = content_hash(f.read_text(encoding="utf-8"))
            hashes.add(h)
        except Exception:
            pass

    log.info("Existing corpus: %d files", len(filenames))
    return hashes, filenames


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scrape benign SKILL.md files from GitHub for corpus expansion",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--target",
        type=int,
        default=80,
        help="Target number of new benign skills to add (default: 80)",
    )
    parser.add_argument(
        "--source",
        choices=["all", "collection", "github"],
        default="all",
        help="Source to scrape from (default: all)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=CORPUS_BENIGN,
        help=f"Output directory (default: {CORPUS_BENIGN})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be fetched without writing files",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Load existing corpus for dedup
    existing_hashes, existing_filenames = load_existing_corpus(args.output_dir)
    initial_count = len(existing_filenames)

    all_fetched: list[dict] = []

    # Allocate target across sources
    if args.source == "all":
        collection_target = int(args.target * 0.6)  # 60% from collection
        github_target = args.target - collection_target  # 40% from search
    elif args.source == "collection":
        collection_target = args.target
        github_target = 0
    else:
        collection_target = 0
        github_target = args.target

    # Fetch from collection
    if collection_target > 0:
        fetched = fetch_from_collection(
            collection_target, existing_hashes, existing_filenames, args.dry_run
        )
        all_fetched.extend(fetched)

    # Fetch from GitHub search (fill remaining target)
    remaining = args.target - len(all_fetched)
    if github_target > 0 and remaining > 0:
        fetched = fetch_from_github_search(
            min(github_target, remaining),
            existing_hashes,
            existing_filenames,
            args.dry_run,
        )
        all_fetched.extend(fetched)

    # Write files
    written = 0
    if not args.dry_run:
        for item in all_fetched:
            out_path = args.output_dir / item["filename"]
            out_path.write_text(item["content"], encoding="utf-8")
            written += 1
            log.debug("  Wrote %s", item["filename"])

    # Summary
    print()
    print("=" * 60)
    print("BENIGN CORPUS SCRAPE SUMMARY")
    print("=" * 60)
    print(f"  Initial corpus size : {initial_count}")
    print(f"  New skills fetched  : {len(all_fetched)}")
    print(f"  Written to disk     : {written}")
    print(f"  Final corpus size   : {initial_count + written}")
    print(f"  Output directory    : {args.output_dir}")
    if args.dry_run:
        print("  (DRY RUN — no files written)")
    print()

    if all_fetched:
        print("  Sample of new skills:")
        for item in all_fetched[:10]:
            print(f"    {item['filename']}")
        if len(all_fetched) > 10:
            print(f"    ... and {len(all_fetched) - 10} more")
    print("=" * 60)

    if not args.dry_run and written > 0:
        print()
        print("  Next steps:")
        print("    git add corpus/benign/")
        print("    git commit -m 'corpus: add benign skills (github-scrape-r4)'")
        print("    git push")


if __name__ == "__main__":
    main()
