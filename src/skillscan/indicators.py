"""indicators.py — post-process model output to extract structured threat indicators.

The v4 generative detector emits `affected_lines` and a free-text `reasoning`
string. By itself that gives "look at line 12"; with this module we add
"…and the curl to evil.example.com on line 12 is the data-exfil endpoint."

Runs at inference time (no retraining). Pure regex extraction over the skill
file content + model reasoning. Indicators are deduped by (type, value) and
capped at 50 per finding.

Indicator types currently extracted:
    url           HTTP(S) URL
    domain        bare domain not appearing inside an http(s) URL
    ip            IPv4 dotted-quad
    package       npm `@scope/name` or pypi-style package on a `pip install`
                  / package.json / requirements.txt line
    cve           CVE-YYYY-NNNN[NNN]
    file_path     absolute or path-traversal style filesystem path
                  (`/etc/passwd`, `~/.ssh/id_rsa`, `../../...`, `C:\\...`)

Designed to be conservative: when in doubt, drop. False indicators are
worse than missing ones because they give downstream tooling bad targets
to act on.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from skillscan.models import Indicator

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

# URL: http(s)://… up to whitespace, bracket/quote terminators, or shell
# substitution markers ($(...), `…`). Including `$` and backtick in the
# exclusion catches `https://x/exfil?d=$(cat ...)` correctly — without
# them the URL would absorb the leading `$(cat`.
# Trailing punctuation (.,;:!?) is stripped post-match because regex can't
# easily distinguish "see https://x.com." (sentence-end) from "https://x.com."
# (path with trailing dot — extremely rare and not worth false-negs).
_URL_RE = re.compile(r"https?://[^\s)>'\"<\]\}$`]+", re.IGNORECASE)

# CVE identifier — case-sensitive (always uppercase in practice; we accept
# either via re.IGNORECASE and uppercase the captured value).
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# IPv4 — dotted quad. Each octet 0-255; this regex over-matches (e.g. 999.x)
# and gets filtered post-match by _is_valid_ipv4.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Bare domain — at least one dot, recognised TLD-style suffix. Excludes
# anything preceded by `://` (URL hostname, captured by URL extractor),
# `@` (email local-part), or `.` (would mean we're matching a SUFFIX of
# a longer host like `nist.gov` inside `nvd.nist.gov`, which would
# duplicate the URL extractor's signal).
_DOMAIN_RE = re.compile(
    r"(?<![\w.@:/-])"  # not preceded by hostname-label chars
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)

# npm package — `@scope/name` or bare `name` quoted in a dependency block.
# We only capture the SCOPED form to avoid over-extracting bare words; the
# requirements.txt / package.json line-context extractor handles unscoped.
_NPM_SCOPED_RE = re.compile(r"@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*", re.IGNORECASE)

# `pip install foo`, `npm install bar`, `npm i baz` — extract everything after.
# Multiple packages on one line are common; split by whitespace.
_INSTALL_LINE_RE = re.compile(
    r"(?:pip\s+install|pip3\s+install|"
    r"npm\s+(?:install|i)|yarn\s+add|pnpm\s+(?:install|add|i))\s+([^\n#]+)",
    re.IGNORECASE,
)

# package.json / requirements.txt entries — captured by line-format heuristic.
_REQUIREMENTS_LINE_RE = re.compile(
    r"^\s*([a-zA-Z0-9][a-zA-Z0-9._-]*?)\s*"
    r"(?:[=<>~!]=?|@)\s*[\w.\-+*]+\s*$"
)

# CVE-style "package@version" in install commands (npm-style).
_PACKAGE_VERSION_RE = re.compile(r"\b([a-z0-9@][a-z0-9._/-]*?)@(\d[\w.\-+]*)\b", re.IGNORECASE)

# File paths (absolute Unix, traversal, Windows, dotfile under home).
_PATH_RE = re.compile(
    r"(?:"
    r"\.\.(?:/\.\.)+(?:/[^\s'\"<>|]+)?"  # relative traversal: ../../etc/passwd
    r"|"
    r"~/\.[a-zA-Z][\w./-]*"  # dotfile under home: ~/.ssh/id_rsa
    r"|"
    r"/(?:etc|var|tmp|usr|root|home|opt|proc|sys|dev|bin|sbin)/[\w./-]*"
    # absolute Unix system paths
    r"|"
    r"[A-Z]:\\\\[\w.\\-]+"  # Windows: C:\Users\...
    r")"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# These domains are conventional and almost always benign — skip to keep
# noise low. False-negs here are acceptable: if a malicious skill points at
# real GitHub-hosted malware, the URL extractor still catches the full URL.
_DOMAIN_NOISE_FLOOR: frozenset[str] = frozenset(
    {
        "github.com",
        "raw.githubusercontent.com",
        "gist.github.com",
        "npmjs.com",
        "registry.npmjs.org",
        "pypi.org",
        "pypi.python.org",
        "files.pythonhosted.org",
        "anthropic.com",
        "openai.com",
        "google.com",
        "googleapis.com",
        "microsoft.com",
        "azure.com",
        "amazonaws.com",
        "cloudflare.com",
        "wikipedia.org",
        "nvd.nist.gov",
        "mitre.org",
        "cve.org",
        "stackoverflow.com",
        "rubygems.org",
        "crates.io",
        "go.dev",
        "docker.io",
        "hub.docker.com",
        "example.com",  # RFC reserved
        "example.org",
        "example.net",
        "localhost",
        "skillscan.dev",
        "skillscan.sh",
    }
)

# Trailing punctuation to strip from URLs/domains (sentence end, parens).
_URL_TRAILING_TRIM = ".,;:!?)\"]'"


def _is_valid_ipv4(s: str) -> bool:
    """Each octet must fit 0-255."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        if not 0 <= int(p) <= 255:
            return False
    return True


def _trim_trailing_punct(s: str) -> str:
    while s and s[-1] in _URL_TRAILING_TRIM:
        s = s[:-1]
    # also balance parens/brackets at end
    if s.count("(") > s.count(")") and s.endswith(")"):
        s = s[:-1]
    return s


def _surrounding_excerpt(text: str, start: int, end: int, width: int = 100) -> str:
    """Short excerpt around match for context; trimmed to single line."""
    lo = max(0, start - width)
    hi = min(len(text), end + width)
    excerpt = text[lo:hi].replace("\n", " ").strip()
    if len(excerpt) > 200:
        excerpt = excerpt[:200].rstrip() + "..."
    return excerpt


def _line_for_offset(text: str, offset: int, line_starts: list[int]) -> int:
    """Map a byte offset into 1-indexed line number using precomputed line_starts."""
    # binary search would be faster; for typical skill files (≤500 lines) linear is fine
    line = 1
    for i, start in enumerate(line_starts):
        if offset < start:
            return max(1, i)
        line = i + 1
    return line


def _line_starts(text: str) -> list[int]:
    starts = [0]
    for m in re.finditer(r"\n", text):
        starts.append(m.end())
    return starts


# ---------------------------------------------------------------------------
# Per-type extractors
# ---------------------------------------------------------------------------


def _extract_urls(text: str, line_starts: list[int]) -> list[Indicator]:
    from skillscan.models import Indicator

    out: list[Indicator] = []
    seen: set[str] = set()
    for m in _URL_RE.finditer(text):
        url = _trim_trailing_punct(m.group(0))
        if len(url) < 12 or url in seen:
            continue
        seen.add(url)
        out.append(
            Indicator(
                type="url",
                value=url,
                line=_line_for_offset(text, m.start(), line_starts),
                evidence=_surrounding_excerpt(text, m.start(), m.end()),
            )
        )
    return out


def _extract_cves(text: str, line_starts: list[int]) -> list[Indicator]:
    from skillscan.models import Indicator

    out: list[Indicator] = []
    seen: set[str] = set()
    for m in _CVE_RE.finditer(text):
        cve = m.group(0).upper()
        if cve in seen:
            continue
        seen.add(cve)
        out.append(
            Indicator(
                type="cve",
                value=cve,
                line=_line_for_offset(text, m.start(), line_starts),
                evidence=_surrounding_excerpt(text, m.start(), m.end()),
            )
        )
    return out


def _extract_ips(text: str, line_starts: list[int]) -> list[Indicator]:
    from skillscan.models import Indicator

    out: list[Indicator] = []
    seen: set[str] = set()
    for m in _IPV4_RE.finditer(text):
        ip = m.group(0)
        if not _is_valid_ipv4(ip) or ip in seen:
            continue
        # Skip localhost-ish noise floor
        if ip.startswith(("127.", "0.0.0.0", "255.255.255.")):
            continue
        seen.add(ip)
        out.append(
            Indicator(
                type="ip",
                value=ip,
                line=_line_for_offset(text, m.start(), line_starts),
                evidence=_surrounding_excerpt(text, m.start(), m.end()),
            )
        )
    return out


def _extract_domains(
    text: str,
    line_starts: list[int],
    seen_url_hosts: set[str],
) -> list[Indicator]:
    """Bare domains. Excludes ones already surfaced as URL hostnames."""
    from skillscan.models import Indicator

    out: list[Indicator] = []
    seen: set[str] = set()
    for m in _DOMAIN_RE.finditer(text):
        d = _trim_trailing_punct(m.group(0)).lower()
        if "." not in d or d in seen:
            continue
        if d in _DOMAIN_NOISE_FLOOR:
            continue
        if d in seen_url_hosts:
            continue
        # Skip common file extensions that look like domains (e.g. README.md,
        # script.sh) — heuristic: if rightmost label is < 2 chars or matches
        # known file ext, drop.
        right = d.rsplit(".", 1)[-1]
        _COMMON_FILE_EXTS = {
            "md",
            "py",
            "sh",
            "js",
            "ts",
            "tsx",
            "jsx",
            "json",
            "yaml",
            "yml",
            "toml",
            "txt",
            "log",
            "html",
            "htm",
        }
        if right in _COMMON_FILE_EXTS:
            continue
        seen.add(d)
        out.append(
            Indicator(
                type="domain",
                value=d,
                line=_line_for_offset(text, m.start(), line_starts),
                evidence=_surrounding_excerpt(text, m.start(), m.end()),
            )
        )
    return out


def _extract_packages(text: str, line_starts: list[int]) -> list[Indicator]:
    """Packages from install commands and dependency lines."""
    from skillscan.models import Indicator

    out: list[Indicator] = []
    seen: set[tuple[str, str]] = set()  # (ecosystem, name)

    # Scoped npm packages anywhere in text
    for m in _NPM_SCOPED_RE.finditer(text):
        name = m.group(0)
        key = ("npm", name.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(
            Indicator(
                type="package",
                value=name,
                line=_line_for_offset(text, m.start(), line_starts),
                evidence=_surrounding_excerpt(text, m.start(), m.end()),
            )
        )

    # `pip install x y z`, `npm install foo bar`
    for m in _INSTALL_LINE_RE.finditer(text):
        rest = m.group(1)
        line = _line_for_offset(text, m.start(), line_starts)
        for token in rest.split():
            tok = token.strip().strip("\"'")
            if not tok or tok.startswith("-"):
                continue  # skip flags
            # tok may include version: pkg@ver, pkg==ver, pkg>=ver
            base = re.split(r"[@=<>~!]", tok, maxsplit=1)[0]
            if not base or len(base) < 2:
                continue
            ecosystem = (
                "npm"
                if "npm" in m.group(0).lower() or "yarn" in m.group(0).lower() or "pnpm" in m.group(0).lower()
                else "pypi"
            )
            key = (ecosystem, base.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append(
                Indicator(
                    type="package",
                    value=tok,
                    line=line,
                    evidence=_surrounding_excerpt(text, m.start(), m.end()),
                )
            )
    return out


def _extract_paths(text: str, line_starts: list[int]) -> list[Indicator]:
    from skillscan.models import Indicator

    out: list[Indicator] = []
    seen: set[str] = set()
    for m in _PATH_RE.finditer(text):
        p = m.group(0)
        if len(p) < 4 or p in seen:
            continue
        seen.add(p)
        out.append(
            Indicator(
                type="file_path",
                value=p,
                line=_line_for_offset(text, m.start(), line_starts),
                evidence=_surrounding_excerpt(text, m.start(), m.end()),
            )
        )
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_indicators(
    skill_text: str,
    reasoning: str = "",
    affected_lines: Iterable[int] | None = None,
    *,
    max_indicators: int = 50,
) -> list[Indicator]:
    """Extract structured indicators from a skill file + model reasoning.

    When `affected_lines` is non-empty, the extractor still scans the full
    file (skill files are small, ~1-3KB typical) but a future enhancement
    can constrain to a window. For now the simplicity is worth it.

    The `reasoning` string is also scanned for CVE references — the model
    often mentions CVEs in its explanation that aren't in the skill text
    itself (e.g. "this is the CVE-2026-XXXXX pattern").

    Returns a list of `Indicator` objects, deduped by (type, value), capped
    at `max_indicators`. Order: skill_text indicators first (which carry
    line numbers), then reasoning-only indicators (line=None).
    """
    from skillscan.models import Indicator  # noqa: F401  — used implicitly

    line_starts = _line_starts(skill_text)
    out: list[Indicator] = []

    # URLs first (also feeds the domain-suppression set)
    urls = _extract_urls(skill_text, line_starts)
    out.extend(urls)
    seen_url_hosts = {_url_host(u.value) for u in urls}

    out.extend(_extract_cves(skill_text, line_starts))
    out.extend(_extract_ips(skill_text, line_starts))
    out.extend(_extract_domains(skill_text, line_starts, seen_url_hosts))
    out.extend(_extract_packages(skill_text, line_starts))
    out.extend(_extract_paths(skill_text, line_starts))

    # Reasoning-only CVEs (model's explanation may name CVEs not in skill text)
    if reasoning:
        reasoning_starts = _line_starts(reasoning)
        seen_cves = {ind.value for ind in out if ind.type == "cve"}
        for m in _CVE_RE.finditer(reasoning):
            cve = m.group(0).upper()
            if cve in seen_cves:
                continue
            seen_cves.add(cve)
            out.append(
                Indicator(
                    type="cve",
                    value=cve,
                    line=None,  # reasoning is not in the skill file
                    evidence=_surrounding_excerpt(reasoning, m.start(), m.end()),
                )
            )
            # don't loop the line_starts variable — referenced for symmetry
            del reasoning_starts

    # Cap and return. Ordering preserved: file-anchored first.
    return out[:max_indicators]


def _url_host(url: str) -> str:
    """Return lowercase host for URL deduplication against domain extractor."""
    m = re.match(r"https?://([^/:?#]+)", url, re.IGNORECASE)
    return m.group(1).lower() if m else ""
