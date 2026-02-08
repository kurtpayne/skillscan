from pathlib import Path

from skillscan.analysis import scan
from skillscan.ecosystems import detect_ecosystems
from skillscan.models import Policy
from skillscan.policies import load_builtin_policy

STRICT = load_builtin_policy("strict")


def _scan(path: str):
    return scan(Path(path), STRICT, "builtin:strict")


def test_showcase_detection_rules() -> None:
    assert any(f.id == "MAL-001" for f in _scan("examples/showcase/01_download_execute").findings)
    assert any(f.id == "MAL-002" for f in _scan("examples/showcase/02_base64_exec").findings)
    assert any(f.id == "ABU-001" for f in _scan("examples/showcase/03_instruction_abuse").findings)
    assert any(f.id == "EXF-001" for f in _scan("examples/showcase/04_secret_access").findings)
    assert any(f.id == "IOC-001" for f in _scan("examples/showcase/05_ioc_match").findings)
    assert any(f.id == "DEP-001" for f in _scan("examples/showcase/06_dep_vuln_python").findings)
    assert any(f.id == "DEP-001" for f in _scan("examples/showcase/07_dep_vuln_npm").findings)
    assert any(f.id == "DEP-UNPIN" for f in _scan("examples/showcase/08_unpinned_deps").findings)
    assert any(f.id == "ABU-001" for f in _scan("examples/showcase/13_zero_width_evasion").findings)
    assert any(f.id == "CHN-001" for f in _scan("examples/showcase/14_base64_hidden_chain").findings)
    assert any(f.id == "CHN-002" for f in _scan("examples/showcase/15_secret_network_chain").findings)
    assert any(f.id == "ABU-002" for f in _scan("examples/showcase/16_privilege_disable_chain").findings)


def test_showcase_policy_block_domain() -> None:
    policy = Policy.model_validate(
        {
            "name": "showcase",
            "description": "showcase",
            "thresholds": {"warn": 30, "block": 70},
            "weights": {
                "malware_pattern": 3,
                "instruction_abuse": 2,
                "exfiltration": 3,
                "dependency_vulnerability": 2,
                "threat_intel": 3,
            },
            "hard_block_rules": ["MAL-001", "IOC-001"],
            "allow_domains": [],
            "block_domains": ["blocked.com"],
            "limits": {
                "max_files": 4000,
                "max_depth": 8,
                "max_bytes": 200000000,
                "timeout_seconds": 60,
            },
        }
    )
    report = scan(Path("examples/showcase/09_policy_block_domain"), policy, "custom")
    assert any(f.id == "POL-IOC-BLOCK" for f in report.findings)


def test_showcase_ecosystem_hints() -> None:
    assert "openai_style" in detect_ecosystems(Path("examples/showcase/10_openai_style"))
    assert "claude_style" in detect_ecosystems(Path("examples/showcase/11_claude_style"))
