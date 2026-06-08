"""Tests for skillscan.triage_hints (Item E: defense-in-depth output integration)."""

from __future__ import annotations

from skillscan.models import IOC, Finding, Indicator, Severity
from skillscan.triage_hints import compute_triage_hints


def _ml_finding(
    *,
    path: str = "skill.md",
    logit_confidence: float | None = 0.99,
    indicators: list[Indicator] | None = None,
) -> Finding:
    return Finding(
        id="PINJ-ML-001",
        category="prompt_injection_ml",
        severity=Severity.HIGH,
        confidence=0.95,
        title="ml hit",
        evidence_path=path,
        logit_confidence=logit_confidence,
        indicators=indicators or [],
    )


def _static_finding(*, id: str = "MAL-001", path: str = "skill.md") -> Finding:
    return Finding(
        id=id,
        category="malware_pattern",
        severity=Severity.HIGH,
        confidence=0.95,
        title="static hit",
        evidence_path=path,
    )


def _advisory_finding(*, id: str = "PINJ-ML-NO-MODEL", path: str = "skill.md") -> Finding:
    return Finding(
        id=id,
        category="prompt_injection_ml",
        severity=Severity.LOW,
        confidence=1.0,
        title="advisory",
        evidence_path=path,
    )


# ---------------------------------------------------------------------------
# H001 ESCALATE_TO_TRACE
# ---------------------------------------------------------------------------


class TestH001EscalateToTrace:
    def test_low_logit_no_corroboration_fires(self):
        findings = [_ml_finding(logit_confidence=0.6)]
        hints = compute_triage_hints(findings, [])
        assert any(h.id == "H001" for h in hints)

    def test_low_logit_with_static_corroboration_does_not_fire(self):
        findings = [
            _ml_finding(logit_confidence=0.6),
            _static_finding(id="MAL-072"),
        ]
        hints = compute_triage_hints(findings, [])
        assert not any(h.id == "H001" for h in hints)

    def test_high_logit_does_not_fire(self):
        findings = [_ml_finding(logit_confidence=0.95)]
        hints = compute_triage_hints(findings, [])
        assert not any(h.id == "H001" for h in hints)

    def test_advisory_finding_does_not_count_as_corroboration(self):
        """A PINJ-ML-NO-MODEL advisory shouldn't suppress H001."""
        findings = [
            _ml_finding(logit_confidence=0.6),
            _advisory_finding(id="PINJ-ML-NO-MODEL"),
        ]
        hints = compute_triage_hints(findings, [])
        assert any(h.id == "H001" for h in hints)

    def test_per_file_isolation(self):
        """File A's static finding shouldn't suppress file B's H001."""
        findings = [
            _ml_finding(path="a.md", logit_confidence=0.6),
            _ml_finding(path="b.md", logit_confidence=0.6),
            _static_finding(id="MAL-001", path="a.md"),
        ]
        hints = [h for h in compute_triage_hints(findings, []) if h.id == "H001"]
        # H001 should fire for b.md but not a.md
        assert len(hints) == 1
        assert "b.md" in hints[0].detail

    def test_logit_none_does_not_fire(self):
        """Older clients without logit_confidence shouldn't trigger H001."""
        findings = [_ml_finding(logit_confidence=None)]
        hints = compute_triage_hints(findings, [])
        assert not any(h.id == "H001" for h in hints)


# ---------------------------------------------------------------------------
# H002 INTEL_GAP
# ---------------------------------------------------------------------------


class TestH002IntelGap:
    def test_indicator_not_in_ioc_db_fires(self):
        f = _ml_finding(
            indicators=[Indicator(type="domain", value="evil-novel.io")],
        )
        hints = compute_triage_hints([f], [])
        assert any(h.id == "H002" for h in hints)

    def test_indicator_in_ioc_db_does_not_fire(self):
        f = _ml_finding(
            indicators=[Indicator(type="domain", value="known-bad.com")],
        )
        iocs = [IOC(value="known-bad.com", kind="domain", source_path="skill.md", listed=True)]
        hints = compute_triage_hints([f], iocs)
        assert not any(h.id == "H002" for h in hints)

    def test_url_normalisation(self):
        """`https://evil.io/x` indicator matches IOC `evil.io/x` (scheme-stripped)."""
        f = _ml_finding(indicators=[Indicator(type="url", value="https://known-bad.com/path")])
        iocs = [IOC(value="known-bad.com/path", kind="url", source_path="skill.md", listed=True)]
        hints = compute_triage_hints([f], iocs)
        assert not any(h.id == "H002" for h in hints)

    def test_non_ioc_backed_types_dont_trigger(self):
        """`package`, `cve`, `file_path` aren't tracked in our IOC DB."""
        f = _ml_finding(
            indicators=[
                Indicator(type="package", value="evil-pkg"),
                Indicator(type="cve", value="CVE-2026-99999"),
                Indicator(type="file_path", value="/etc/passwd"),
            ],
        )
        hints = compute_triage_hints([f], [])
        assert not any(h.id == "H002" for h in hints)

    def test_partial_match_still_emits_for_unmatched(self):
        f = _ml_finding(
            indicators=[
                Indicator(type="domain", value="known-bad.com"),
                Indicator(type="domain", value="novel-bad.io"),
            ],
        )
        iocs = [IOC(value="known-bad.com", kind="domain", source_path="skill.md", listed=True)]
        hints = compute_triage_hints([f], iocs)
        h002 = [h for h in hints if h.id == "H002"]
        assert len(h002) == 1
        assert "novel-bad.io" in h002[0].detail
        assert "known-bad.com" not in h002[0].detail


# ---------------------------------------------------------------------------
# H003 STRONG_CORROBORATION
# ---------------------------------------------------------------------------


class TestH003Corroboration:
    def test_ml_plus_static_fires(self):
        findings = [_ml_finding(), _static_finding(id="SUP-042")]
        hints = compute_triage_hints(findings, [])
        h003 = [h for h in hints if h.id == "H003"]
        assert len(h003) == 1
        assert "SUP-042" in h003[0].detail
        assert "PINJ-ML-001" in h003[0].detail

    def test_ml_alone_does_not_fire(self):
        findings = [_ml_finding()]
        hints = compute_triage_hints(findings, [])
        assert not any(h.id == "H003" for h in hints)

    def test_static_alone_does_not_fire(self):
        findings = [_static_finding()]
        hints = compute_triage_hints(findings, [])
        assert not any(h.id == "H003" for h in hints)

    def test_per_file_grouping(self):
        findings = [
            _ml_finding(path="a.md"),
            _static_finding(id="MAL-001", path="a.md"),
            _ml_finding(path="b.md"),  # b.md has no static rule
        ]
        h003 = [h for h in compute_triage_hints(findings, []) if h.id == "H003"]
        assert len(h003) == 1
        assert "a.md" in h003[0].detail


# ---------------------------------------------------------------------------
# Integration smoke
# ---------------------------------------------------------------------------


class TestComputeTriageHints:
    def test_empty_findings_returns_empty(self):
        assert compute_triage_hints([], []) == []

    def test_returns_list_of_TriageHint(self):
        from skillscan.models import TriageHint

        findings = [_ml_finding(logit_confidence=0.6)]
        hints = compute_triage_hints(findings, [])
        assert all(isinstance(h, TriageHint) for h in hints)

    def test_realistic_uncertain_ml_only_scenario(self):
        """Common Item-E payoff case: low-conf ML + no static + novel indicators."""
        f = _ml_finding(
            logit_confidence=0.62,
            indicators=[
                Indicator(type="url", value="https://novel-c2.example.com/exfil"),
                Indicator(type="ip", value="203.0.113.42"),
            ],
        )
        hints = compute_triage_hints([f], [])
        ids = {h.id for h in hints}
        assert "H001" in ids  # ML uncertain + no corroboration
        assert "H002" in ids  # indicators not in IOC DB
        assert "H003" not in ids  # no static corroboration
