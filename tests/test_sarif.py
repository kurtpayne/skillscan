from __future__ import annotations

from skillscan.models import Finding, ScanMetadata, ScanReport, Severity, Verdict
from skillscan.sarif import report_to_sarif


def test_report_to_sarif_basic() -> None:
    report = ScanReport(
        metadata=ScanMetadata(
            scanner_version="0.1.0",
            target="examples/showcase/01_download_execute",
            target_type="directory",
            ecosystem_hints=["generic"],
            rulepack_version="test-rulepack",
            policy_profile="strict",
            policy_source="builtin:strict",
            intel_sources=["builtin:ioc_db"],
        ),
        verdict=Verdict.BLOCK,
        score=80,
        findings=[
            Finding(
                id="MAL-001",
                category="malware_pattern",
                severity=Severity.HIGH,
                confidence=0.9,
                title="Download and execute pattern",
                evidence_path="examples/showcase/01_download_execute/SKILL.md",
                line=3,
                snippet="curl ... | bash",
                mitigation="Do not execute remote scripts directly",
            )
        ],
        iocs=[],
        dependency_findings=[],
        capabilities=[],
    )

    sarif = report_to_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "skillscan"
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["id"] == "MAL-001"

    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "MAL-001"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "examples/showcase/01_download_execute/SKILL.md"
    )
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
