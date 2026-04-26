"""triage_hints.py — defense-in-depth output integration (Item E).

The scanner has 4 detection layers (static rules, IOC matching, ML,
optional behavioral trace). Today they fire independently. This module
runs AFTER all layers have fired and emits cross-layer recommendations:

    H001 ESCALATE_TO_TRACE      — ML uncertain (logit_confidence < 0.7)
                                  AND no static-rule corroboration on the
                                  same file → run skillscan-trace.

    H002 INTEL_GAP              — ML/static finding has indicators
                                  (URL/domain/IP) that aren't present in
                                  the IOC database → consider
                                  `skillscan intel refresh`.

    H003 STRONG_CORROBORATION   — ML + static rule (and optionally IOC)
                                  all fire on the same file → high-
                                  confidence detection (informational).

Hints are advisory; they do NOT change the verdict or score. They surface
in `ScanReport.triage_hints` and downstream consumers can render them
however they like (text section, SARIF properties, etc.).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from skillscan.models import IOC, Finding, TriageHint

# logit_confidence below this triggers ESCALATE_TO_TRACE (when no
# static-rule corroboration). Picked to match the v4.7 held-out eval:
# 100% of ML errors live below 0.80; 0.70 is a slightly more permissive
# threshold that still captures the true uncertainty band.
_ESCALATE_LOGIT_THRESHOLD = 0.70

# These detection-finding ID prefixes count as "static-rule corroboration"
# for ESCALATE_TO_TRACE. Anything else (advisories, semantic-classifier
# findings, ML findings themselves) does NOT corroborate.
_STATIC_RULE_PREFIXES: frozenset[str] = frozenset(
    {
        "MAL-",
        "PSV-",
        "PINJ-",
        "SUP-",
        "CAP-",
        "OBF-",
        "SE-",
        "EXF-",
        "GR-",
        "CHN-",
        "CVE-",  # CVE-IDs that fire as standalone rules
    }
)

# Indicator types that map to IOC-database lookups. Other indicator
# types (package, file_path, cve) aren't tracked in our IOC DB structure
# (which is URL/domain/IP-centric).
_IOC_BACKED_INDICATOR_TYPES: frozenset[str] = frozenset({"url", "domain", "ip"})

# Findings IDs that should be EXCLUDED from corroboration counting —
# advisories, ML model itself, etc.
_NON_CORROBORATING_IDS: frozenset[str] = frozenset(
    {
        "PINJ-ML-001",
        "PINJ-ML-NO-MODEL",
        "PINJ-ML-STALE",
        "PINJ-ML-LARGE-FILE",
        "PINJ-ML-UNAVAIL",
        "PINJ-SEM-001",  # local semantic classifier — same layer as ML conceptually
    }
)


def _is_static_rule_finding(f: Finding) -> bool:
    if f.id in _NON_CORROBORATING_IDS:
        return False
    return any(f.id.startswith(p) for p in _STATIC_RULE_PREFIXES)


def _normalise_ioc_value(v: str) -> str:
    """Lowercase, strip scheme — for cross-referencing indicators against IOCs."""
    v = v.strip().lower()
    if v.startswith(("http://", "https://")):
        v = v.split("://", 1)[1]
    return v.rstrip("/")


def compute_triage_hints(
    findings: Iterable[Finding],
    iocs: Iterable[IOC] | None = None,
) -> list[TriageHint]:
    """Return defense-in-depth recommendations derived from cross-layer signal.

    Runs once per scan, after all detection layers have populated the
    findings list. Output is a list of TriageHint objects (may be empty).

    Args:
        findings: All findings from this scan, across all layers.
        iocs: Matched IOCs from this scan (already filtered to the
            indicators that DO appear in the IOC DB). Indicators in
            findings that DON'T appear here flag an intel gap.
    """
    findings = list(findings)
    iocs = list(iocs or [])

    # Normalise IOC values once for fast membership checks
    known_ioc_values: set[str] = {_normalise_ioc_value(ioc.value) for ioc in iocs}

    # Group findings by file (evidence_path) for per-file cross-layer reasoning
    by_path: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_path[f.evidence_path].append(f)

    hints: list[TriageHint] = []

    # H001 ESCALATE_TO_TRACE
    for path, file_findings in by_path.items():
        ml_uncertain: list[Finding] = [
            f
            for f in file_findings
            if f.id == "PINJ-ML-001"
            and f.logit_confidence is not None
            and f.logit_confidence < _ESCALATE_LOGIT_THRESHOLD
        ]
        if not ml_uncertain:
            continue
        has_static_corroboration = any(_is_static_rule_finding(f) for f in file_findings)
        if has_static_corroboration:
            continue
        confs = [f.logit_confidence for f in ml_uncertain if f.logit_confidence is not None]
        min_conf = min(confs) if confs else 0.0
        hints.append(
            TriageHint(
                id="H001",
                title="ML detected with low confidence — recommend behavioral verification",
                detail=(
                    f"{path}: PINJ-ML-001 fired at logit_confidence "
                    f"{min_conf:.3f} (below {_ESCALATE_LOGIT_THRESHOLD:.2f}) "
                    "with no static-rule corroboration. The model is uncertain; "
                    "behavioral execution can confirm or refute."
                ),
                recommendation=(f"Run: skillscan-trace run {path} --provider <openai|anthropic|openrouter>"),
                related_finding_ids=[f.id for f in ml_uncertain],
            )
        )

    # H002 INTEL_GAP — collect indicators across all findings, check against known IOCs
    indicator_gaps: dict[str, list[str]] = defaultdict(list)  # path → unmatched values
    for path, file_findings in by_path.items():
        for f in file_findings:
            for ind in f.indicators:
                if ind.type not in _IOC_BACKED_INDICATOR_TYPES:
                    continue
                if _normalise_ioc_value(ind.value) in known_ioc_values:
                    continue
                if ind.value not in indicator_gaps[path]:
                    indicator_gaps[path].append(ind.value)

    for path, gaps in indicator_gaps.items():
        if not gaps:
            continue
        sample = ", ".join(gaps[:5])
        more = f" (+ {len(gaps) - 5} more)" if len(gaps) > 5 else ""
        hints.append(
            TriageHint(
                id="H002",
                title="Indicators not in IOC database — possible intel gap",
                detail=(
                    f"{path}: indicators extracted from this finding "
                    "are not present in the bundled IOC DB. They may be "
                    "novel infrastructure not yet attributed. "
                    f"Indicators: {sample}{more}."
                ),
                recommendation=(
                    "Run: skillscan intel refresh "
                    "(or manually verify these indicators against external "
                    "threat-intel sources before clearing the file)."
                ),
                related_finding_ids=[
                    f.id
                    for f in by_path[path]
                    if any(
                        ind.type in _IOC_BACKED_INDICATOR_TYPES
                        and _normalise_ioc_value(ind.value) not in known_ioc_values
                        for ind in f.indicators
                    )
                ],
            )
        )

    # H003 STRONG_CORROBORATION — multi-layer agreement
    for path, file_findings in by_path.items():
        has_ml = any(f.id == "PINJ-ML-001" for f in file_findings)
        has_static = any(_is_static_rule_finding(f) for f in file_findings)
        if not (has_ml and has_static):
            continue
        ml_ids = sorted({f.id for f in file_findings if f.id == "PINJ-ML-001"})
        static_ids = sorted({f.id for f in file_findings if _is_static_rule_finding(f)})
        hints.append(
            TriageHint(
                id="H003",
                title="Multi-layer detection — high-confidence finding",
                detail=(
                    f"{path}: ML detector and static rules independently "
                    f"flagged this file. Static: {', '.join(static_ids)}. "
                    f"ML: {', '.join(ml_ids)}."
                ),
                recommendation=("No additional action required — the verdict is well-corroborated."),
                related_finding_ids=ml_ids + static_ids,
            )
        )

    return hints
