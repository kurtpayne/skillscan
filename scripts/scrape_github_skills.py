#!/usr/bin/env python3
"""
scrape_github_skills.py — Round 2 corpus expansion: real-world benign SKILL.md scraper.

Searches GitHub for SKILL.md files in public repositories, downloads them,
filters for quality, deduplicates against the existing corpus, and writes
clean benign examples to corpus/benign/.

Usage:
    python3 scripts/scrape_github_skills.py [--dry-run] [--limit N] [--output DIR]

Requirements:
    - GH_TOKEN env var (or gh CLI token) with public repo read access
    - pip install requests PyYAML

Corpus expansion log entry is appended to docs/CORPUS_EXPANSION.md.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

import requests
import yaml

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent
CORPUS_BENIGN = REPO_ROOT / "corpus" / "benign"
CORPUS_MANIFEST = REPO_ROOT / "corpus" / "manifest.json"
LOG_FILE = REPO_ROOT / "corpus" / "scrape_log.jsonl"

# GitHub code search API
GH_API = "https://api.github.com"
SEARCH_QUERIES = [
    "filename:SKILL.md path:/",
    "filename:SKILL.md allowed-tools",
    "filename:SKILL.md description tools",
    "filename:SKILL.md name description examples",
]

# Quality filter thresholds
MIN_BODY_CHARS = 100
MIN_FIELDS = 1  # at least one of: name, description, tools, allowed-tools
MAX_FILE_BYTES = 32_000  # skip huge files

# Known attack pattern signals — files matching these are NOT benign
ATTACK_SIGNALS = [
    r"ignore (previous|all|prior|above) instructions?",
    r"you are now (DAN|an? AI without|an? unrestricted)",
    r"jailbreak",
    r"pretend (you are|to be) (an? )?(AI|assistant|model) (without|that (ignores|has no))",
    r"do not (refuse|decline|say no)",
    r"system prompt.*override",
    r"<\|im_start\|>system",
    r"IGNORE ALL PREVIOUS",
    r"bypass (safety|filter|restriction|guideline)",
    r"act as if you have no (restriction|filter|safety|guideline)",
]
ATTACK_RE = re.compile("|".join(ATTACK_SIGNALS), re.IGNORECASE)

# Existing corpus SHA256s for dedup
_EXISTING_HASHES: set[str] = set()


def _get_token() -> str:
    """Get GitHub token from env or gh CLI."""
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        import subprocess
        result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
        if result.returncode == 0:
            token = result.stdout.strip()
    if not token:
        print("ERROR: No GitHub token found. Set GH_TOKEN or run 'gh auth login'.", file=sys.stderr)
        sys.exit(1)
    return token


def _load_existing_hashes() -> set[str]:
    """Load SHA256 hashes of all existing corpus files for dedup."""
    hashes = set()
    for f in CORPUS_BENIGN.glob("*.md"):
        content = f.read_bytes()
        hashes.add(hashlib.sha256(content).hexdigest())
    # Also check manifest
    if CORPUS_MANIFEST.exists():
        manifest = json.loads(CORPUS_MANIFEST.read_text())
        for entry in manifest.get("examples", []):
            if "sha256" in entry:
                hashes.add(entry["sha256"])
    return hashes


def _search_github(query: str, token: str, page: int = 1) -> dict:
    """Run a GitHub code search query."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    params = {"q": query, "per_page": 100, "page": page}
    resp = requests.get(f"{GH_API}/search/code", headers=headers, params=params, timeout=30)
    if resp.status_code == 403:
        # Rate limited
        reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
        wait = max(reset - int(time.time()), 10)
        print(f"  Rate limited. Waiting {wait}s...", flush=True)
        time.sleep(wait)
        return _search_github(query, token, page)
    if resp.status_code == 422:
        # Query too complex or no results
        return {"items": [], "total_count": 0}
    resp.raise_for_status()
    return resp.json()


def _download_raw(url: str, token: str) -> Optional[bytes]:
    """Download raw file content from GitHub."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.raw+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.content
        return None
    except Exception:
        return None


def _parse_skill_md(content: bytes) -> Optional[dict]:
    """
    Parse a SKILL.md file. Returns dict with parsed fields or None if invalid.
    """
    try:
        text = content.decode("utf-8", errors="replace").strip()
    except Exception:
        return None

    if not text.startswith("---"):
        # Try to find front-matter anywhere in first 500 chars
        if "---" not in text[:500]:
            return None
        text = text[text.index("---"):]

    # Split front-matter
    parts = text.split("---", 2)
    if len(parts) < 3:
        return None

    front_matter_str = parts[1].strip()
    body = parts[2].strip()

    if len(body) < MIN_BODY_CHARS:
        return None

    try:
        fm = yaml.safe_load(front_matter_str) or {}
    except yaml.YAMLError:
        return None

    if not isinstance(fm, dict):
        return None

    # Must have at least one meaningful field
    meaningful = {"name", "description", "tools", "allowed-tools", "allowed_tools"}
    if not meaningful.intersection(set(fm.keys())):
        return None

    return {"front_matter": fm, "body": body, "raw": text}


def _is_benign(content: bytes, parsed: dict) -> bool:
    """Check that a file doesn't contain attack patterns."""
    text = content.decode("utf-8", errors="replace")
    if ATTACK_RE.search(text):
        return False
    return True


def _make_filename(fm: dict, repo: str, sha: str) -> str:
    """Generate a safe corpus filename."""
    name = fm.get("name", "")
    if name:
        slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")[:40]
    else:
        slug = sha[:8]
    repo_slug = re.sub(r"[^a-z0-9]+", "_", repo.lower().replace("/", "_"))[:20]
    return f"gh_{repo_slug}_{slug}.md"


def _add_corpus_metadata(content: str, repo: str, source_url: str, round_date: str) -> str:
    """Inject corpus provenance metadata as YAML comments."""
    lines = content.split("\n")
    # Find the closing --- of front-matter
    fm_end = -1
    in_fm = False
    for i, line in enumerate(lines):
        if i == 0 and line.strip() == "---":
            in_fm = True
            continue
        if in_fm and line.strip() == "---":
            fm_end = i
            break

    if fm_end == -1:
        return content

    meta_lines = [
        f"# corpus-label: benign",
        f"# corpus-source: github-scrape",
        f"# corpus-repo: {repo}",
        f"# corpus-url: {source_url}",
        f"# corpus-round: {round_date}",
    ]
    lines = lines[:fm_end] + meta_lines + lines[fm_end:]
    return "\n".join(lines)


def scrape(
    dry_run: bool = False,
    limit: int = 300,
    output_dir: Optional[Path] = None,
    round_date: str = "2026-03-19",
) -> dict:
    """
    Main scrape function. Returns summary dict.
    """
    global _EXISTING_HASHES

    output_dir = output_dir or CORPUS_BENIGN
    output_dir.mkdir(parents=True, exist_ok=True)

    token = _get_token()
    _EXISTING_HASHES = _load_existing_hashes()

    print(f"Existing corpus hashes loaded: {len(_EXISTING_HASHES)}")
    print(f"Output directory: {output_dir}")
    print(f"Target: {limit} new benign examples")
    print(f"Dry run: {dry_run}")
    print()

    seen_urls: set[str] = set()
    candidates: list[dict] = []

    for query in SEARCH_QUERIES:
        if len(candidates) >= limit * 3:  # gather 3x candidates for filtering
            break
        print(f"Searching: {query!r}", flush=True)
        for page in range(1, 11):  # max 10 pages = 1000 results per query
            try:
                result = _search_github(query, token, page)
            except Exception as e:
                print(f"  Search error: {e}", flush=True)
                break

            items = result.get("items", [])
            if not items:
                break

            for item in items:
                url = item.get("url", "")
                html_url = item.get("html_url", "")
                repo = item.get("repository", {}).get("full_name", "")
                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)
                candidates.append({
                    "url": url,
                    "html_url": html_url,
                    "repo": repo,
                    "sha": item.get("sha", ""),
                })

            print(f"  Page {page}: {len(items)} results, {len(candidates)} candidates total", flush=True)
            time.sleep(1)  # respect rate limits

            if len(items) < 100:
                break  # last page

        time.sleep(2)

    print(f"\nTotal candidates: {len(candidates)}")
    print("Downloading and filtering...\n")

    accepted = []
    rejected_counts = {
        "duplicate": 0,
        "parse_fail": 0,
        "attack_signal": 0,
        "too_small": 0,
        "too_large": 0,
        "download_fail": 0,
    }

    for i, candidate in enumerate(candidates):
        if len(accepted) >= limit:
            break

        if i % 50 == 0:
            print(f"  Progress: {i}/{len(candidates)} checked, {len(accepted)} accepted", flush=True)

        # Download
        raw_content = _download_raw(candidate["url"], token)
        if raw_content is None:
            rejected_counts["download_fail"] += 1
            continue

        if len(raw_content) > MAX_FILE_BYTES:
            rejected_counts["too_large"] += 1
            continue

        # Dedup
        sha256 = hashlib.sha256(raw_content).hexdigest()
        if sha256 in _EXISTING_HASHES:
            rejected_counts["duplicate"] += 1
            continue

        # Parse
        parsed = _parse_skill_md(raw_content)
        if parsed is None:
            rejected_counts["parse_fail"] += 1
            continue

        # Attack signal check
        if not _is_benign(raw_content, parsed):
            rejected_counts["attack_signal"] += 1
            _log_entry(LOG_FILE, {
                "action": "rejected_attack_signal",
                "repo": candidate["repo"],
                "url": candidate["html_url"],
                "round": round_date,
            })
            continue

        # Accepted
        _EXISTING_HASHES.add(sha256)
        filename = _make_filename(parsed["front_matter"], candidate["repo"], candidate["sha"])

        # Add provenance metadata
        annotated = _add_corpus_metadata(
            parsed["raw"],
            candidate["repo"],
            candidate["html_url"],
            round_date,
        )

        accepted.append({
            "filename": filename,
            "content": annotated,
            "repo": candidate["repo"],
            "url": candidate["html_url"],
            "sha256": sha256,
        })

        _log_entry(LOG_FILE, {
            "action": "accepted",
            "filename": filename,
            "repo": candidate["repo"],
            "url": candidate["html_url"],
            "sha256": sha256,
            "round": round_date,
        })

        time.sleep(0.2)  # gentle rate limiting

    print(f"\nAccepted: {len(accepted)}")
    print(f"Rejected: {rejected_counts}")

    if not dry_run:
        for item in accepted:
            out_path = output_dir / item["filename"]
            out_path.write_text(item["content"], encoding="utf-8")
        print(f"\nWrote {len(accepted)} files to {output_dir}")
    else:
        print("\n[DRY RUN] No files written.")
        for item in accepted[:5]:
            print(f"  Would write: {item['filename']} (from {item['repo']})")

    summary = {
        "round": round_date,
        "accepted": len(accepted),
        "rejected": rejected_counts,
        "candidates_checked": min(i + 1, len(candidates)),
        "output_dir": str(output_dir),
    }

    _log_entry(LOG_FILE, {"action": "scrape_complete", "summary": summary})
    return summary


def _log_entry(log_file: Path, entry: dict) -> None:
    """Append a JSONL log entry."""
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, "a") as f:
        f.write(json.dumps(entry) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Scrape real-world SKILL.md files from GitHub")
    parser.add_argument("--dry-run", action="store_true", help="Don't write files")
    parser.add_argument("--limit", type=int, default=250, help="Max new examples to add")
    parser.add_argument("--output", type=Path, default=None, help="Output directory")
    parser.add_argument("--round-date", default="2026-03-19", help="Round date for provenance")
    args = parser.parse_args()

    summary = scrape(
        dry_run=args.dry_run,
        limit=args.limit,
        output_dir=args.output,
        round_date=args.round_date,
    )

    print("\n=== SCRAPE SUMMARY ===")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
