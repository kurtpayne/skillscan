"""Tests for the v4 generative ML detector (ml_detector.py).

These tests run without the GGUF model or llama-cpp-python installed.
They verify helper functions and graceful degradation.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from skillscan.ml_detector import (
    _map_severity,
    _parse_model_output,
    _strip_label_fields,
    ml_prompt_injection_findings,
)
from skillscan.models import Severity

# ---------------------------------------------------------------------------
# _strip_label_fields
# ---------------------------------------------------------------------------


class TestStripLabelFields:
    def test_strips_attack_labels(self):
        text = "---\nname: test\nlabel: injection\nattack_labels:\n- path_traversal\n---\n# Body"
        result = _strip_label_fields(text)
        assert "attack_labels" not in result
        assert "path_traversal" not in result
        assert "name: test" in result
        assert "# Body" in result

    def test_keeps_legitimate_metadata(self):
        text = (
            "---\nname: test-skill\nversion: '1.0'\n"
            "description: A test\ntags: [test]\nlabel: benign\n---\nBody"
        )
        result = _strip_label_fields(text)
        assert "name: test-skill" in result
        assert "version:" in result
        assert "description:" in result
        assert "label:" not in result

    def test_no_frontmatter(self):
        text = "# Just a heading\n\nSome text."
        assert _strip_label_fields(text) == text

    def test_strips_confidence_and_source(self):
        text = "---\nname: x\nconfidence: 5\nsource: manual\nevasion_technique: none\n---\nBody"
        result = _strip_label_fields(text)
        assert "confidence" not in result
        assert "source" not in result
        assert "evasion_technique" not in result


# ---------------------------------------------------------------------------
# _parse_model_output
# ---------------------------------------------------------------------------


class TestParseModelOutput:
    def test_valid_json(self):
        raw = (
            '{"verdict": "malicious", "labels": ["path_traversal"],'
            ' "confidence": 0.9, "reasoning": "Uses ../../etc/passwd"}'
        )
        result = _parse_model_output(raw)
        assert result is not None
        assert result["verdict"] == "malicious"
        assert result["labels"] == ["path_traversal"]

    def test_json_in_code_fence(self):
        raw = '```json\n{"verdict": "benign", "labels": [], "confidence": 0.95, "reasoning": "Safe."}\n```'
        result = _parse_model_output(raw)
        assert result is not None
        assert result["verdict"] == "benign"

    def test_invalid_json(self):
        raw = "This is not JSON at all"
        result = _parse_model_output(raw)
        assert result is None


# ---------------------------------------------------------------------------
# _map_severity
# ---------------------------------------------------------------------------


class TestMapSeverity:
    def test_high_confidence(self):
        assert _map_severity(0.9, "prompt_injection") == Severity.HIGH

    def test_medium_confidence(self):
        assert _map_severity(0.6, "prompt_injection") == Severity.MEDIUM

    def test_low_confidence(self):
        assert _map_severity(0.3, "prompt_injection") == Severity.LOW

    def test_exfil_escalation(self):
        assert _map_severity(0.9, "data_exfiltration") == Severity.CRITICAL

    def test_supply_chain_escalation(self):
        assert _map_severity(0.85, "supply_chain") == Severity.CRITICAL

    def test_supply_chain_medium_no_escalation(self):
        assert _map_severity(0.6, "supply_chain") == Severity.MEDIUM


# ---------------------------------------------------------------------------
# ml_prompt_injection_findings — integration (mocked model)
# ---------------------------------------------------------------------------


class TestMlFindings:
    def test_no_model_installed(self):
        """When model file doesn't exist, return PINJ-ML-NO-MODEL finding."""
        with patch("skillscan.model_sync.get_model_status") as mock_status:
            mock_status.return_value = MagicMock(installed=False, stale=False, warn=False)
            findings = ml_prompt_injection_findings(Path("test.md"), "some text")
            assert len(findings) >= 1
            assert findings[0].id == "PINJ-ML-NO-MODEL"

    def test_empty_text(self):
        findings = ml_prompt_injection_findings(Path("test.md"), "")
        assert findings == []
