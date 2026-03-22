#!/usr/bin/env python3
"""Fetch benign skills from alirezarezvani/claude-skills (462 skills)."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = "alirezarezvani/claude-skills"
CORPUS = Path("/home/ubuntu/skillscan-security/corpus/benign")
ROUND = "2026-03-21"
SOURCE_TAG = "github-scrape-r4"
TARGET = int(sys.argv[1]) if len(sys.argv) > 1 else 50

INJECTION_RE = re.compile(
    r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\b"
    r"|\boverride\s+(?:your\s+)?(?:instructions?|system|prompt|directive)\b"
    r"|\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\b"
    r"|\bforget\s+(?:all\s+)?(?:previous|prior|your)\b"
    r"|\bact\s+as\s+(?:a\s+)?(?:DAN|jailbreak|unrestricted)\b"
    r"|\bAGENT\s+DIRECTIVE\b"
    r"|\bexfiltrat\w+\b"
    r"|\bsilently\s+(?:execute|run|perform|send|delete)\b"
    r"|\bskip\s+(?:confirmation|approval|review|human)\b",
    re.IGNORECASE | re.MULTILINE,
)


def existing_filenames():
    return {f.name for f in CORPUS.glob("*.md")}


def existing_hashes():
    hs = set()
    for f in CORPUS.glob("*.md"):
        try:
            hs.add(hashlib.sha256(f.read_text().strip().encode()).hexdigest())
        except Exception:
            pass
    return hs


def fetch(path):
    r = subprocess.run(
        ["gh", "api", f"repos/{REPO}/contents/{path}"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return None
    try:
        d = json.loads(r.stdout)
    except json.JSONDecodeError:
        return None
    if d.get("encoding") == "base64":
        try:
            return base64.b64decode(d["content"]).decode("utf-8", errors="replace")
        except Exception:
            return None
    return d.get("content")


def make_name(path):
    p = Path(path)
    owner_s = "alirezarezva"
    repo_s = "claudeskills"
    # Use parent dir name as skill name when file is SKILL.md
    if p.name.upper() == "SKILL.MD":
        skill_s = re.sub(r"[^a-z0-9_]", "_", p.parent.name.lower())[:28].strip("_")
    else:
        skill_s = re.sub(r"[^a-z0-9_]", "_", p.stem.lower())[:28].strip("_")
    return f"gh_{owner_s}_{repo_s}_{skill_s}.md"


def wrap(content, path, url):
    p = Path(path)
    if p.name.upper() == "SKILL.MD":
        name = p.parent.name.replace("-", " ").replace("_", " ")
    else:
        name = p.stem.replace("-", " ").replace("_", " ")
    desc_m = re.search(
        r"^(?:description|##\s+(?:Purpose|Overview|Description))[:\s]+(.+)$",
        content, re.MULTILINE | re.IGNORECASE,
    )
    description = desc_m.group(1).strip()[:120] if desc_m else f"Community skill: {name}"
    fm = f"""---
name: {name}
version: "1.0"
description: {description}
category: community
# corpus-label: benign
# corpus-source: {SOURCE_TAG}
# corpus-repo: {REPO}
# corpus-url: {url}
# corpus-round: {ROUND}
# corpus-format: markdown_fm
---
"""
    body = content
    if content.startswith("---"):
        end = content.find("\n---", 3)
        if end != -1:
            body = content[end + 4:].strip()
    return fm + body


def main():
    # Load tree
    r = subprocess.run(
        ["gh", "api", f"repos/{REPO}/git/trees/HEAD?recursive=1",
         "--jq", '.tree[] | select(.path | test("SKILL.md$"; "i")) | .path'],
        capture_output=True, text=True,
    )
    paths = [
        p for p in r.stdout.strip().splitlines()
        if p and "TEMPLATE" not in p.upper() and "README" not in p.upper()
    ]
    print(f"Found {len(paths)} skill paths in {REPO}")

    filenames = existing_filenames()
    hashes = existing_hashes()
    print(f"Existing corpus: {len(filenames)} files")

    written = 0
    skipped = 0
    errors = 0

    for path in paths:
        if written >= TARGET:
            break
        filename = make_name(path)
        if filename in filenames:
            skipped += 1
            continue
        content = fetch(path)
        if not content or len(content.strip()) < 100:
            errors += 1
            continue
        if INJECTION_RE.search(content):
            skipped += 1
            continue
        h = hashlib.sha256(content.strip().encode()).hexdigest()
        if h in hashes:
            skipped += 1
            continue
        url = f"https://github.com/{REPO}/blob/HEAD/{path}"
        wrapped = wrap(content, path, url)
        out = CORPUS / filename
        out.write_text(wrapped, encoding="utf-8")
        filenames.add(filename)
        hashes.add(h)
        written += 1
        if written % 10 == 0:
            print(f"  Written {written}/{TARGET}...")
        time.sleep(0.3)

    print(f"\nDone: written={written} skipped={skipped} errors={errors}")
    print(f"Corpus now has {len(filenames)} files")


if __name__ == "__main__":
    main()
