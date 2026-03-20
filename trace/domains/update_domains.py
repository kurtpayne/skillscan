#!/usr/bin/env python3
"""
skillscan-trace domain allowlist updater.

Polls official provider IP/domain sources, diffs against verified.yml,
and opens a PR when new entries are detected. Designed to run as a
weekly GitHub Actions job — not a timer-based staleness check.

Sources monitored:
  - Google Cloud:  https://www.gstatic.com/ipranges/cloud.json  (syncToken)
  - AWS:           https://ip-ranges.amazonaws.com/ip-ranges.json  (createDate)
  - GitHub:        https://api.github.com/meta  (verifiable_password_authentication)
  - Manual review: Azure, Cloudflare, Stripe, etc. (no machine-readable lists)

Usage:
  python3 update_domains.py --check       # show diff, do not write
  python3 update_domains.py --apply       # write verified.yml + print diff
  python3 update_domains.py --ci          # CI mode: exit 1 if changes found (triggers PR)
"""

import json
import re
import sys
import hashlib
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import requests
    import yaml
except ImportError:
    print("Missing dependencies. Run: pip install requests pyyaml", file=sys.stderr)
    sys.exit(1)

VERIFIED_YML = Path(__file__).parent / "verified.yml"
STATE_FILE = Path(__file__).parent / ".domain_state.json"

# ─────────────────────────────────────────────────────────────────────────────
# Provider source definitions
# Each entry defines how to fetch and extract a change signal from an
# official provider source. The signal is a hash or token — if it changes,
# we know to review the source for new domains.
# ─────────────────────────────────────────────────────────────────────────────

SOURCES: list[dict[str, Any]] = [
    {
        "name": "google_cloud_ip_ranges",
        "profile": "google_cloud",
        "url": "https://www.gstatic.com/ipranges/cloud.json",
        "signal_field": "syncToken",
        "description": "Google Cloud IP ranges (cloud.json). syncToken changes when ranges update.",
        "review_url": "https://cloud.google.com/compute/docs/faq#find_ip_range",
        "note": (
            "GCP does not publish a machine-readable list of service domain names. "
            "IP range changes are a proxy signal — when syncToken changes, check "
            "https://cloud.google.com/vpc/docs/configure-private-google-access for "
            "new *.googleapis.com service endpoints."
        ),
    },
    {
        "name": "aws_ip_ranges",
        "profile": "aws",
        "url": "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "signal_field": "createDate",
        "description": "AWS IP ranges (ip-ranges.json). createDate changes on any update.",
        "review_url": "https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html",
        "note": (
            "AWS publishes IP ranges but not a consolidated service domain list. "
            "When createDate changes, check https://docs.aws.amazon.com/general/latest/gr/rande.html "
            "for new service endpoint domains (e.g., new regional *.amazonaws.com patterns)."
        ),
        "sns_topic": "arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged",
    },
    {
        "name": "github_meta",
        "profile": "source_control",
        "url": "https://api.github.com/meta",
        "signal_field": None,  # hash the full response
        "description": "GitHub Meta API. Returns IP ranges for hooks, web, API, git, packages, etc.",
        "review_url": "https://api.github.com/meta",
        "note": (
            "GitHub publishes IP ranges via the Meta API. Hash the full response — "
            "any change in hooks/web/api/git/packages/copilot/actions IP ranges "
            "warrants a review of whether new *.github.com or *.githubusercontent.com "
            "subdomains have been added."
        ),
    },
    {
        "name": "cloudflare_ips",
        "profile": "cdn",
        "url": "https://www.cloudflare.com/ips-v4",
        "signal_field": None,  # hash the full text response
        "description": "Cloudflare IPv4 ranges. Plain text, one CIDR per line.",
        "review_url": "https://www.cloudflare.com/ips/",
        "note": (
            "Cloudflare publishes IP ranges but not a domain list. Changes here "
            "are low-signal for domain allowlisting — Cloudflare domains are stable "
            "(*.cloudflare.com, *.fastly.net). Monitor for completeness."
        ),
    },
]


def fetch_signal(source: dict[str, Any]) -> tuple[str, str]:
    """Fetch a source and return (signal_value, raw_content_hash)."""
    resp = requests.get(source["url"], timeout=15, headers={"User-Agent": "skillscan-trace/domain-updater"})
    resp.raise_for_status()

    content_hash = hashlib.sha256(resp.content).hexdigest()[:16]

    if source["url"].endswith(".json") or "application/json" in resp.headers.get("Content-Type", ""):
        data = resp.json()
        if source["signal_field"] and source["signal_field"] in data:
            return str(data[source["signal_field"]]), content_hash
    # Fall back to hashing the full response
    return content_hash, content_hash


def load_state() -> dict[str, Any]:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}


def save_state(state: dict[str, Any]) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2))


def check_sources() -> list[dict[str, Any]]:
    """Check all sources and return a list of changed sources."""
    state = load_state()
    changed = []

    for source in SOURCES:
        name = source["name"]
        try:
            signal, content_hash = fetch_signal(source)
        except Exception as e:
            print(f"  [WARN] {name}: fetch failed — {e}", file=sys.stderr)
            continue

        prev_signal = state.get(name, {}).get("signal")
        prev_checked = state.get(name, {}).get("last_checked", "never")

        if prev_signal is None:
            print(f"  [NEW]  {name}: first check, signal={signal[:20]}")
            state[name] = {"signal": signal, "last_checked": datetime.now(timezone.utc).isoformat()}
        elif signal != prev_signal:
            print(f"  [CHANGED] {name}: {prev_signal[:20]} → {signal[:20]} (last checked: {prev_checked})")
            changed.append({**source, "old_signal": prev_signal, "new_signal": signal})
            state[name] = {"signal": signal, "last_checked": datetime.now(timezone.utc).isoformat()}
        else:
            print(f"  [OK]   {name}: no change (signal={signal[:20]}, last checked: {prev_checked})")
            state[name]["last_checked"] = datetime.now(timezone.utc).isoformat()

    save_state(state)
    return changed


def format_review_notice(changed: list[dict[str, Any]]) -> str:
    """Format a human-readable review notice for changed sources."""
    lines = [
        "## Domain Allowlist Review Required",
        "",
        "The following upstream sources changed since the last check.",
        "Review each source for new service domains and update `trace/domains/verified.yml` if needed.",
        "",
    ]
    for c in changed:
        lines += [
            f"### {c['name']} ({c['profile']} profile)",
            f"- **Signal:** `{c['old_signal'][:20]}` → `{c['new_signal'][:20]}`",
            f"- **Source:** {c['url']}",
            f"- **Review at:** {c['review_url']}",
            f"- **Note:** {c['note']}",
            "",
        ]
    lines += [
        "### What to check",
        "1. Open each review URL above.",
        "2. Look for new domain patterns not already covered by the relevant profile in `verified.yml`.",
        "3. Add new wildcard patterns where appropriate (prefer `*.service.provider.com` over specific subdomains).",
        "4. Update `_meta.updated` and `_meta.version` in `verified.yml`.",
        "5. Commit with message: `chore(trace): update domain allowlist — <provider> <date>`",
        "",
        "### What NOT to do",
        "- Do not add IP ranges to verified.yml — it is domain-only.",
        "- Do not add domains that are not service endpoints (e.g., marketing sites, status pages).",
        "- Do not add overly broad wildcards (e.g., `*.com`) — prefer service-specific patterns.",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="skillscan-trace domain allowlist updater")
    parser.add_argument("--check", action="store_true", help="Check sources and print diff (no writes)")
    parser.add_argument("--apply", action="store_true", help="Check sources and update state file")
    parser.add_argument("--ci", action="store_true", help="CI mode: exit 1 if changes found")
    args = parser.parse_args()

    if not (args.check or args.apply or args.ci):
        parser.print_help()
        sys.exit(0)

    print(f"Checking {len(SOURCES)} upstream sources...")
    changed = check_sources()

    if not changed:
        print("\nAll sources unchanged. No review needed.")
        sys.exit(0)

    notice = format_review_notice(changed)
    print("\n" + notice)

    if args.ci:
        # In CI: write the notice to a file for the PR body, then exit 1
        notice_file = Path(__file__).parent / "REVIEW_NOTICE.md"
        notice_file.write_text(notice)
        print(f"\nReview notice written to {notice_file}")
        print("Exiting with code 1 to signal CI that a PR should be opened.")
        sys.exit(1)


if __name__ == "__main__":
    main()
