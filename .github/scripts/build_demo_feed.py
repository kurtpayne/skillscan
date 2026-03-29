#!/usr/bin/env python3
"""Build the SkillScan demo feed JSON from skill-index.yaml.

Reads all entries with role=demo_feed from the index, scans each one using
skillscan, and writes a structured JSON file suitable for the website.

Usage:
    python3 build_demo_feed.py \\
        --index path/to/skill-index.yaml \\
        --output demo-feed.json \\
        [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--index", required=True, help="Path to skill-index.yaml")
    p.add_argument("--output", required=True, help="Output JSON path")
    p.add_argument("--dry-run", action="store_true", help="Print results without writing output")
    return p.parse_args()


def load_index(index_path: str) -> list[dict]:
    """Load skill-index.yaml and return all demo_feed entries."""
    import yaml  # available in CI via pip install pyyaml

    with open(index_path) as f:
        idx = yaml.safe_load(f)

    entries = []
    for entry in idx.get("entries", []):
        roles = entry.get("roles", [])
        if "demo_feed" in roles:
            entries.append(entry)

    return entries


def scan_entry(entry: dict, corpus_root: Path) -> dict:
    """Run skillscan on a single demo feed entry and return result dict."""
    entry_id = entry["id"]
    path = entry.get("path")
    url = entry.get("url")
    expected = entry.get("demo_verdict_expected", "UNKNOWN")

    # Resolve the skill file path
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir) / "SKILL.md"

        if path:
            # Local corpus file
            skill_file = corpus_root / path
            if not skill_file.exists():
                return _error_result(entry, f"File not found: {skill_file}")
            tmp_path.write_text(skill_file.read_text(encoding="utf-8"), encoding="utf-8")
        elif url:
            # External URL — fetch with timeout
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "skillscan-demo-feed/1.0"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    content = resp.read().decode("utf-8", errors="replace")
                tmp_path.write_text(content, encoding="utf-8")
            except Exception as e:
                return _error_result(entry, f"Fetch failed: {e}")
        else:
            return _error_result(entry, "No path or url in index entry")

        # Run skillscan
        try:
            result = subprocess.run(
                ["skillscan", "scan", str(tmp_path), "--format", "json"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            output = result.stdout.strip()
        except subprocess.TimeoutExpired:
            return _error_result(entry, "Scan timed out after 60s")
        except Exception as e:
            return _error_result(entry, f"Scan failed: {e}")

    # Parse verdict from JSON output
    verdict = "ERROR"
    findings = []
    top_rule = None
    severity = None

    try:
        scan_data = json.loads(output)
        # skillscan JSON output: {"verdict": "block"|"allow"|"warn", "findings": [...], ...}
        # Normalise to uppercase; treat "warn" as BLOCK (findings detected above threshold)
        raw_verdict = scan_data.get("verdict", "error").lower()
        verdict = "BLOCK" if raw_verdict in ("block", "warn") else ("ALLOW" if raw_verdict == "allow" else "ERROR")
        raw_findings = scan_data.get("findings", [])
        findings = [
            {
                "rule_id": f.get("rule_id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", ""),
                "confidence": f.get("confidence", ""),
            }
            for f in raw_findings[:5]  # top 5 findings only
        ]
        if raw_findings:
            top_rule = raw_findings[0].get("rule_id", "")
            severity = raw_findings[0].get("severity", "")
    except (json.JSONDecodeError, KeyError):
        # Fallback: scan stderr/stdout plain text for verdict keywords
        for line in output.splitlines():
            line_up = line.upper()
            if "BLOCK" in line_up or "WARN" in line_up:
                verdict = "BLOCK"
                break
            elif "ALLOW" in line_up:
                verdict = "ALLOW"
                break

    return {
        "id": entry_id,
        "demo_title": entry.get("demo_title", entry_id),
        "demo_description": entry.get("demo_description", ""),
        "label": entry.get("label", "unknown"),
        "archetype": entry.get("archetype", ""),
        "rule_id": entry.get("rule_id", top_rule or ""),
        "reference": entry.get("reference", ""),
        "verdict": verdict,
        "expected_verdict": expected,
        "verdict_match": verdict == expected,
        "severity": severity or "",
        "findings_count": len(findings),
        "top_findings": findings,
        "scanned_at": datetime.now(UTC).isoformat(),
    }


def _error_result(entry: dict, message: str) -> dict:
    return {
        "id": entry["id"],
        "demo_title": entry.get("demo_title", entry["id"]),
        "demo_description": entry.get("demo_description", ""),
        "label": entry.get("label", "unknown"),
        "archetype": entry.get("archetype", ""),
        "rule_id": entry.get("rule_id", ""),
        "reference": entry.get("reference", ""),
        "verdict": "ERROR",
        "expected_verdict": entry.get("demo_verdict_expected", "UNKNOWN"),
        "verdict_match": False,
        "severity": "",
        "findings_count": 0,
        "top_findings": [],
        "error": message,
        "scanned_at": datetime.now(UTC).isoformat(),
    }


def main() -> None:
    args = parse_args()
    index_path = Path(args.index)

    if not index_path.exists():
        print(f"ERROR: Index not found: {index_path}", file=sys.stderr)
        sys.exit(1)

    # Corpus root is two levels above index/skill-index.yaml
    corpus_root = index_path.parent.parent

    print(f"Loading demo feed entries from {index_path}")
    entries = load_index(str(index_path))
    print(f"Found {len(entries)} demo_feed entries")

    results = []
    for i, entry in enumerate(entries, 1):
        print(f"[{i}/{len(entries)}] Scanning: {entry['id']} ...", end=" ", flush=True)
        result = scan_entry(entry, corpus_root)
        verdict = result["verdict"]
        match = "✓" if result["verdict_match"] else "✗"
        print(f"{verdict} {match}")
        results.append(result)

    # Summary
    blocks = sum(1 for r in results if r["verdict"] == "BLOCK")
    allows = sum(1 for r in results if r["verdict"] == "ALLOW")
    errors = sum(1 for r in results if r["verdict"] == "ERROR")
    unexpected = [r for r in results if not r["verdict_match"]]

    print(f"\nResults: {len(results)} scanned — BLOCK={blocks}, ALLOW={allows}, ERROR={errors}")
    if unexpected:
        print(f"WARNING: {len(unexpected)} unexpected verdicts:")
        for r in unexpected:
            print(f"  {r['id']}: expected {r['expected_verdict']}, got {r['verdict']}")
    else:
        print("All verdicts match expected.")

    output = {
        "generated_at": datetime.now(UTC).isoformat(),
        "skillscan_version": _get_skillscan_version(),
        "entry_count": len(results),
        "block_count": blocks,
        "allow_count": allows,
        "error_count": errors,
        "unexpected_count": len(unexpected),
        "entries": results,
    }

    if args.dry_run:
        print("\n[dry-run] Output JSON preview (first 2 entries):")
        preview = {**output, "entries": results[:2]}
        print(json.dumps(preview, indent=2))
        print(f"\n[dry-run] Would write {len(results)} entries to {args.output}")
    else:
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\nWrote {args.output} ({Path(args.output).stat().st_size} bytes)")

    # Exit non-zero if there are unexpected verdicts (fails CI)
    if unexpected:
        sys.exit(1)


def _get_skillscan_version() -> str:
    try:
        result = subprocess.run(
            ["skillscan", "version"], capture_output=True, text=True, timeout=5
        )
        # Output: "SkillScan (skillscan-security) 0.8.0"
        for line in result.stdout.splitlines():
            if line.strip():
                return line.strip().split()[-1]
        return result.stdout.strip().split()[-1]
    except Exception:
        return "unknown"


if __name__ == "__main__":
    main()
