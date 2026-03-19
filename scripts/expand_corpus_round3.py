#!/usr/bin/env python3
"""
expand_corpus_round3.py — Round 3 corpus expansion: ChatGPT/OpenAI-style skills + broader search.

Extends the existing benign corpus with:
  - ChatGPT custom GPT instruction files (INSTRUCTIONS.md, system_prompt.md, etc.)
  - OpenAI Assistants API instruction files
  - CLAUDE.md files with MCP tool declarations
  - Broader MCP skill file patterns (.mcp.json, agent_skill.md, etc.)
  - Additional SKILL.md queries using different keyword combinations

The scraper is dedup-aware: it loads all existing corpus SHA256s and skips
any file already in the corpus. Pagination is exhaustive (10 pages × 100 = 1,000
results per query, the GitHub Search API maximum).

Usage:
    python3 scripts/expand_corpus_round3.py [--dry-run] [--limit N] [--output DIR]

Requirements:
    - GH_TOKEN env var with public repo read access
    - pip install requests PyYAML
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import date
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

GH_API = "https://api.github.com"

# ---------------------------------------------------------------------------
# Search query groups
# ---------------------------------------------------------------------------
# Each entry is (label, query_string).
# We run up to 10 pages per query (GitHub Search API max = 1,000 results).
# Queries are ordered from most-specific to broadest so we fill the candidate
# pool with the highest-quality files first.

SEARCH_QUERIES: list[tuple[str, str]] = [
    # ── Existing SKILL.md patterns (already in scraper — kept for new pages) ──
    ("skill_md_root",          "filename:SKILL.md path:/"),
    ("skill_md_allowed_tools", "filename:SKILL.md allowed-tools"),
    ("skill_md_description",   "filename:SKILL.md description tools"),
    ("skill_md_name_examples", "filename:SKILL.md name description examples"),

    # ── CLAUDE.md with MCP tool declarations ──
    ("claude_md_tools",        "filename:CLAUDE.md allowed-tools"),
    ("claude_md_mcp",          "filename:CLAUDE.md mcp tools"),
    ("claude_md_skill",        "filename:CLAUDE.md skill description"),

    # ── ChatGPT custom GPT instruction files ──
    ("gpt_instructions_md",    "filename:INSTRUCTIONS.md custom GPT instructions"),
    ("gpt_instructions_md2",   "filename:INSTRUCTIONS.md You are a GPT"),
    ("gpt_instructions_md3",   "filename:INSTRUCTIONS.md You are an AI assistant"),
    ("chatgpt_instructions",   "filename:chatgpt_instructions.md"),
    ("gpt_instructions_txt",   "filename:gpt_instructions.txt"),
    ("system_prompt_md",       "filename:system_prompt.md"),
    ("system_prompt_txt",      "filename:system_prompt.txt"),
    ("gpt_system_prompt",      "filename:system_prompt.md You are"),

    # ── OpenAI Assistants API ──
    ("assistant_instructions", "filename:assistant_instructions.md"),
    ("openai_assistant_md",    "filename:openai_assistant.md"),
    ("assistant_config",       "filename:assistant_config.yaml instructions"),

    # ── MCP / agent skill file patterns ──
    ("mcp_json",               "filename:.mcp.json tools"),
    ("agent_skill_md",         "filename:agent_skill.md"),
    ("skill_config_yaml",      "filename:skill_config.yaml description"),
    ("skill_yaml_allowed",     "filename:skill.yaml allowed-tools"),
    ("skill_yaml_name",        "filename:skill.yaml name description version"),

    # ── Broader skill file patterns ──
    ("skill_md_version",       "filename:SKILL.md version"),
    ("skill_md_tags",          "filename:SKILL.md tags"),
    ("skill_md_safety",        "filename:SKILL.md safety"),
    ("skill_md_overview",      "filename:SKILL.md Overview"),
    ("skill_md_usage",         "filename:SKILL.md Usage"),
    ("skill_md_notes",         "filename:SKILL.md Notes"),

    # ── Alternate capitalisations and naming conventions ──
    ("skill_lowercase",        "filename:skill.md allowed-tools"),
    ("skill_lowercase_desc",   "filename:skill.md description name version"),
    ("claude_md_instructions", "filename:CLAUDE.md instructions"),
    ("claude_md_overview",     "filename:CLAUDE.md Overview"),
]

# ---------------------------------------------------------------------------
# Quality / safety filters
# ---------------------------------------------------------------------------

MIN_BODY_CHARS = 80
MIN_FIELDS = 1
MAX_FILE_BYTES = 48_000

# Files matching these patterns are NOT benign — skip them
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
    r"disregard (your|all) (previous|prior|above) (instructions?|training|guidelines?)",
    r"you have no (restrictions?|limitations?|filters?)",
    r"developer mode",
    r"DAN mode",
]
ATTACK_RE = re.compile("|".join(ATTACK_SIGNALS), re.IGNORECASE)

# Files that are clearly not skill/instruction files
SKIP_PATTERNS = [
    r"^\s*#\s*(TODO|FIXME|HACK|NOTE):",  # plain dev notes
]
SKIP_RE = re.compile("|".join(SKIP_PATTERNS), re.IGNORECASE)

_EXISTING_HASHES: set[str] = set()


# ---------------------------------------------------------------------------
# GitHub helpers
# ---------------------------------------------------------------------------

def _get_token() -> str:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        import subprocess
        result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
        if result.returncode == 0:
            token = result.stdout.strip()
    if not token:
        print("ERROR: No GitHub token. Set GH_TOKEN or run 'gh auth login'.", file=sys.stderr)
        sys.exit(1)
    return token


def _load_existing_hashes() -> set[str]:
    hashes: set[str] = set()
    for f in CORPUS_BENIGN.glob("*.md"):
        hashes.add(hashlib.sha256(f.read_bytes()).hexdigest())
    if CORPUS_MANIFEST.exists():
        manifest = json.loads(CORPUS_MANIFEST.read_text())
        for v in manifest.get("sha256_index", {}).values():
            hashes.add(v)
    return hashes


def _search_github(query: str, token: str, page: int = 1) -> dict:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    params = {"q": query, "per_page": 100, "page": page}
    while True:
        resp = requests.get(f"{GH_API}/search/code", headers=headers, params=params, timeout=30)
        if resp.status_code == 403:
            reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait = max(reset - int(time.time()), 15)
            print(f"  Rate limited. Waiting {wait}s...", flush=True)
            time.sleep(wait)
            continue
        if resp.status_code == 422:
            return {"items": [], "total_count": 0}
        if resp.status_code == 429:
            time.sleep(30)
            continue
        resp.raise_for_status()
        return resp.json()


def _download_raw(url: str, token: str) -> Optional[bytes]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.raw+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        return resp.content if resp.status_code == 200 else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_skill_file(content: bytes, filename: str) -> Optional[dict]:
    """
    Parse a skill/instruction file. Accepts:
    - SKILL.md / CLAUDE.md / agent_skill.md: YAML front-matter + Markdown body
    - system_prompt.md / INSTRUCTIONS.md: plain text or YAML front-matter
    - .mcp.json / skill.yaml: JSON or YAML
    - gpt_instructions.txt: plain text
    """
    try:
        text = content.decode("utf-8", errors="replace").strip()
    except Exception:
        return None

    fname_lower = filename.lower()

    # JSON files
    if fname_lower.endswith(".json"):
        try:
            data = json.loads(text)
            if isinstance(data, dict) and ("tools" in data or "instructions" in data):
                return {"front_matter": data, "body": json.dumps(data, indent=2), "raw": text, "format": "json"}
        except Exception:
            pass
        return None

    # YAML files
    if fname_lower.endswith((".yaml", ".yml")):
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict):
                meaningful = {"name", "description", "tools", "allowed-tools", "allowed_tools", "instructions"}
                if meaningful.intersection(set(data.keys())):
                    return {"front_matter": data, "body": text, "raw": text, "format": "yaml"}
        except Exception:
            pass
        return None

    # Markdown / text files
    if text.startswith("---"):
        # YAML front-matter
        parts = text.split("---", 2)
        if len(parts) >= 3:
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
            meaningful = {"name", "description", "tools", "allowed-tools", "allowed_tools", "instructions"}
            if meaningful.intersection(set(fm.keys())):
                return {"front_matter": fm, "body": body, "raw": text, "format": "markdown_fm"}
        return None
    else:
        # Plain text / prose instructions (ChatGPT style)
        # Accept if: long enough and looks like instructions
        if len(text) < MIN_BODY_CHARS:
            return None
        instruction_signals = [
            r"you are (a|an|the)\b",
            r"your (role|job|task|goal|purpose) is",
            r"you (should|must|will|can|cannot|are able to)",
            r"when (the user|a user|users?)\b",
            r"do not\b",
            r"always\b",
            r"never\b",
            r"respond (in|with|to)\b",
        ]
        signal_re = re.compile("|".join(instruction_signals), re.IGNORECASE)
        if signal_re.search(text):
            return {"front_matter": {}, "body": text, "raw": text, "format": "plain_instructions"}
        return None


def _is_benign(content: bytes) -> bool:
    text = content.decode("utf-8", errors="replace")
    return not ATTACK_RE.search(text)


def _make_filename(fm: dict, repo: str, sha: str, source_filename: str) -> str:
    name = fm.get("name", "")
    if name:
        slug = re.sub(r"[^a-z0-9]+", "_", str(name).lower()).strip("_")[:40]
    else:
        # Derive slug from source filename
        base = Path(source_filename).stem.lower()
        slug = re.sub(r"[^a-z0-9]+", "_", base).strip("_")[:40] or sha[:8]
    repo_slug = re.sub(r"[^a-z0-9]+", "_", repo.lower().replace("/", "_"))[:20]
    return f"gh_{repo_slug}_{slug}.md"


def _add_corpus_metadata(content: str, repo: str, source_url: str, round_date: str, fmt: str) -> str:
    """Inject corpus provenance metadata. For non-front-matter files, prepend as a comment block."""
    if content.startswith("---"):
        lines = content.split("\n")
        fm_end = -1
        in_fm = False
        for i, line in enumerate(lines):
            if i == 0 and line.strip() == "---":
                in_fm = True
                continue
            if in_fm and line.strip() == "---":
                fm_end = i
                break
        if fm_end != -1:
            meta_lines = [
                "# corpus-label: benign",
                "# corpus-source: github-scrape-r3",
                f"# corpus-repo: {repo}",
                f"# corpus-url: {source_url}",
                f"# corpus-round: {round_date}",
                f"# corpus-format: {fmt}",
            ]
            lines = lines[:fm_end] + meta_lines + lines[fm_end:]
            return "\n".join(lines)
    # Plain text / JSON / YAML — prepend comment block
    meta = "\n".join([
        "---",
        "# corpus-label: benign",
        "# corpus-source: github-scrape-r3",
        f"# corpus-repo: {repo}",
        f"# corpus-url: {source_url}",
        f"# corpus-round: {round_date}",
        f"# corpus-format: {fmt}",
        "---",
        "",
    ])
    return meta + content


def _log_entry(entry: dict) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Main scrape function
# ---------------------------------------------------------------------------

def scrape(
    dry_run: bool = False,
    limit: int = 500,
    output_dir: Optional[Path] = None,
    round_date: Optional[str] = None,
    queries: Optional[list[tuple[str, str]]] = None,
) -> dict:
    global _EXISTING_HASHES

    round_date = round_date or str(date.today())
    output_dir = output_dir or CORPUS_BENIGN
    output_dir.mkdir(parents=True, exist_ok=True)
    queries = queries or SEARCH_QUERIES

    token = _get_token()
    _EXISTING_HASHES = _load_existing_hashes()

    print(f"Round: {round_date}")
    print(f"Existing corpus hashes: {len(_EXISTING_HASHES)}")
    print(f"Output directory: {output_dir}")
    print(f"Target: {limit} new benign examples")
    print(f"Queries: {len(queries)}")
    print(f"Dry run: {dry_run}")
    print()

    seen_urls: set[str] = set()
    candidates: list[dict] = []

    for label, query in queries:
        print(f"[{label}] Searching: {query!r}", flush=True)
        total_for_query = 0

        for page in range(1, 11):  # max 10 pages = 1,000 results per query
            try:
                result = _search_github(query, token, page)
            except Exception as e:
                print(f"  Search error on page {page}: {e}", flush=True)
                break

            items = result.get("items", [])
            total_count = result.get("total_count", 0)

            if page == 1:
                print(f"  Total available: {total_count}", flush=True)

            if not items:
                break

            new_this_page = 0
            for item in items:
                url = item.get("url", "")
                html_url = item.get("html_url", "")
                repo = item.get("repository", {}).get("full_name", "")
                source_filename = item.get("name", "SKILL.md")
                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)
                candidates.append({
                    "url": url,
                    "html_url": html_url,
                    "repo": repo,
                    "sha": item.get("sha", ""),
                    "filename": source_filename,
                    "query_label": label,
                })
                new_this_page += 1

            total_for_query += new_this_page
            print(f"  Page {page}/{min(10, (total_count + 99)//100)}: +{new_this_page} new candidates ({len(candidates)} total)", flush=True)
            time.sleep(1.5)  # respect secondary rate limits

            if len(items) < 100:
                break  # last page

        print(f"  → {total_for_query} candidates from this query\n", flush=True)
        time.sleep(3)  # pause between queries

    print(f"Total candidates collected: {len(candidates)}")
    print("Downloading and filtering...\n")

    accepted: list[dict] = []
    rejected_counts: dict[str, int] = {
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

        if i % 100 == 0 and i > 0:
            print(f"  Progress: {i}/{len(candidates)} checked, {len(accepted)} accepted", flush=True)

        # Download
        raw_content = _download_raw(candidate["url"], token)
        if raw_content is None:
            rejected_counts["download_fail"] += 1
            continue

        if len(raw_content) > MAX_FILE_BYTES:
            rejected_counts["too_large"] += 1
            continue

        if len(raw_content) < MIN_BODY_CHARS:
            rejected_counts["too_small"] += 1
            continue

        # Dedup
        sha256 = hashlib.sha256(raw_content).hexdigest()
        if sha256 in _EXISTING_HASHES:
            rejected_counts["duplicate"] += 1
            continue

        # Attack signal check
        if not _is_benign(raw_content):
            rejected_counts["attack_signal"] += 1
            _log_entry({
                "action": "rejected_attack_signal",
                "repo": candidate["repo"],
                "url": candidate["html_url"],
                "round": round_date,
            })
            continue

        # Parse
        parsed = _parse_skill_file(raw_content, candidate["filename"])
        if parsed is None:
            rejected_counts["parse_fail"] += 1
            continue

        # Accepted
        _EXISTING_HASHES.add(sha256)
        filename = _make_filename(
            parsed["front_matter"],
            candidate["repo"],
            candidate["sha"],
            candidate["filename"],
        )

        annotated = _add_corpus_metadata(
            parsed["raw"],
            candidate["repo"],
            candidate["html_url"],
            round_date,
            parsed.get("format", "unknown"),
        )

        accepted.append({
            "filename": filename,
            "content": annotated,
            "repo": candidate["repo"],
            "url": candidate["html_url"],
            "sha256": sha256,
            "query_label": candidate["query_label"],
            "format": parsed.get("format", "unknown"),
        })

        _log_entry({
            "action": "accepted",
            "filename": filename,
            "repo": candidate["repo"],
            "url": candidate["html_url"],
            "sha256": sha256,
            "query_label": candidate["query_label"],
            "format": parsed.get("format", "unknown"),
            "round": round_date,
        })

        time.sleep(0.15)

    print(f"\nAccepted: {len(accepted)}")
    print(f"Rejected breakdown: {json.dumps(rejected_counts, indent=2)}")

    # Format breakdown
    fmt_counts: dict[str, int] = {}
    for item in accepted:
        fmt_counts[item["format"]] = fmt_counts.get(item["format"], 0) + 1
    print(f"Format breakdown: {json.dumps(fmt_counts, indent=2)}")

    if not dry_run:
        for item in accepted:
            out_path = output_dir / item["filename"]
            out_path.write_text(item["content"], encoding="utf-8")
        print(f"\nWrote {len(accepted)} files to {output_dir}")
    else:
        print("\n[DRY RUN] No files written.")
        for item in accepted[:10]:
            print(f"  Would write: {item['filename']} [{item['format']}] (from {item['repo']})")

    summary = {
        "round": round_date,
        "accepted": len(accepted),
        "rejected": rejected_counts,
        "format_breakdown": fmt_counts,
        "candidates_checked": min(i + 1, len(candidates)),
        "total_candidates": len(candidates),
        "output_dir": str(output_dir),
    }
    _log_entry({"action": "scrape_complete", "summary": summary})
    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Round 3 corpus expansion: ChatGPT/OpenAI skills + broader search"
    )
    parser.add_argument("--dry-run", action="store_true", help="Don't write files")
    parser.add_argument("--limit", type=int, default=500, help="Max new examples to add (default: 500)")
    parser.add_argument("--output", type=Path, default=None, help="Output directory")
    parser.add_argument("--round-date", default=str(date.today()), help="Round date for provenance")
    parser.add_argument(
        "--query-group",
        choices=["all", "skill_md", "claude_md", "chatgpt", "openai", "mcp", "broad"],
        default="all",
        help="Run only a subset of queries",
    )
    args = parser.parse_args()

    # Filter queries by group if requested
    group_prefixes = {
        "skill_md": ["skill_md"],
        "claude_md": ["claude_md"],
        "chatgpt": ["gpt_", "chatgpt", "system_prompt"],
        "openai": ["assistant", "openai"],
        "mcp": ["mcp_", "agent_skill", "skill_config", "skill_yaml"],
        "broad": ["skill_lowercase", "claude_md_instructions", "claude_md_overview"],
    }

    if args.query_group == "all":
        queries = SEARCH_QUERIES
    else:
        prefixes = group_prefixes[args.query_group]
        queries = [(l, q) for l, q in SEARCH_QUERIES if any(l.startswith(p) for p in prefixes)]
        print(f"Running {len(queries)} queries for group '{args.query_group}'")

    summary = scrape(
        dry_run=args.dry_run,
        limit=args.limit,
        output_dir=args.output,
        round_date=args.round_date,
        queries=queries,
    )

    print("\n=== ROUND 3 SCRAPE SUMMARY ===")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
