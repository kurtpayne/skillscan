import json
from pathlib import Path

from skillscan.analysis import scan
from skillscan.intel import add_source
from skillscan.models import Policy, Verdict
from skillscan.policies import load_builtin_policy


def test_malicious_fixture_blocks() -> None:
    policy = load_builtin_policy("strict")
    target = Path("tests/fixtures/malicious/openclaw_compromised_like")
    report = scan(target, policy, "builtin:strict")
    assert report.verdict == Verdict.BLOCK
    assert any(f.id == "MAL-001" for f in report.findings)


def test_benign_fixture_allows_or_warns() -> None:
    policy = load_builtin_policy("balanced")
    target = Path("tests/fixtures/benign/basic_skill")
    report = scan(target, policy, "builtin:balanced")
    assert report.verdict in {Verdict.ALLOW, Verdict.WARN}


def test_dependency_fixture_flags_vuln_and_unpinned() -> None:
    policy = load_builtin_policy("balanced")
    target = Path("tests/fixtures/dependencies")
    report = scan(target, policy, "builtin:balanced")
    ids = {f.id for f in report.findings}
    assert "DEP-001" in ids
    assert "DEP-UNPIN" in ids


def test_policy_block_domain_adds_finding() -> None:
    policy = Policy.model_validate(
        {
            "name": "test",
            "description": "test",
            "thresholds": {"warn": 1, "block": 2},
            "weights": {"threat_intel": 1},
            "hard_block_rules": [],
            "allow_domains": [],
            "block_domains": ["blocked.com"],
            "limits": {"max_files": 100, "max_depth": 4, "max_bytes": 1000000, "timeout_seconds": 10},
        }
    )
    target = Path("tests/fixtures/policy")
    report = scan(target, policy, "custom")
    assert any(f.id == "POL-IOC-BLOCK" for f in report.findings)


def test_cidr_ioc_match(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SKILLSCAN_HOME", str(tmp_path / ".skillscan"))
    custom_ioc = tmp_path / "cidr_iocs.json"
    custom_ioc.write_text(
        json.dumps({"domains": [], "ips": [], "urls": [], "cidrs": ["203.0.113.0/24"]}),
        encoding="utf-8",
    )
    add_source(name="cidr-test", kind="ioc", source_path=custom_ioc)
    policy = load_builtin_policy("strict")
    target = Path("tests/fixtures/policy")
    report = scan(target, policy, "builtin:strict")
    assert any(f.id == "IOC-001" for f in report.findings)
