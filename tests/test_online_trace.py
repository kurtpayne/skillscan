"""Tests for the online-trace CLI command."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
import typer.testing

from skillscan.cli import app
from skillscan.commands.online_trace import (
    _format_md,
    _format_text,
    _read_skill,
    _resolve_api_key,
    _verdict_exit_code,
)

runner = typer.testing.CliRunner()


# ---------------------------------------------------------------------------
# Unit tests for helpers
# ---------------------------------------------------------------------------


class TestVerdictExitCode:
    def test_pass(self) -> None:
        assert _verdict_exit_code("pass") == 0
        assert _verdict_exit_code("PASS") == 0

    def test_block(self) -> None:
        assert _verdict_exit_code("block") == 1
        assert _verdict_exit_code("BLOCK") == 1

    def test_review(self) -> None:
        assert _verdict_exit_code("review") == 2
        assert _verdict_exit_code("inconclusive") == 2

    def test_unknown(self) -> None:
        assert _verdict_exit_code("something_else") == 3


class TestReadSkill:
    def test_reads_file(self, tmp_path: Path) -> None:
        f = tmp_path / "SKILL.md"
        f.write_text("hello")
        assert _read_skill(f) == "hello"

    def test_reads_directory(self, tmp_path: Path) -> None:
        (tmp_path / "SKILL.md").write_text("from dir")
        assert _read_skill(tmp_path) == "from dir"

    def test_missing_file_exits(self, tmp_path: Path) -> None:
        with pytest.raises((SystemExit, typer.Exit)):
            _read_skill(tmp_path / "nonexistent.md")

    def test_directory_without_skill_md_exits(self, tmp_path: Path) -> None:
        with pytest.raises((SystemExit, typer.Exit)):
            _read_skill(tmp_path)


class TestResolveApiKey:
    def test_explicit_key(self) -> None:
        assert _resolve_api_key("openai", "sk-test") == "sk-test"

    def test_env_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-from-env")
        assert _resolve_api_key("openai", None) == "sk-from-env"

    def test_missing_key_exits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises((SystemExit, typer.Exit)):
            _resolve_api_key("openai", None)
