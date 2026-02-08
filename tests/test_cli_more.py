from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from skillscan.cli import app

runner = CliRunner()


def test_version_and_policy_commands() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "skillscan" in result.stdout

    show = runner.invoke(app, ["policy", "show-default", "--profile", "strict"])
    assert show.exit_code == 0
    assert "strict" in show.stdout


def test_scan_invalid_options() -> None:
    target = "tests/fixtures/benign/basic_skill"
    invalid_format = runner.invoke(app, ["scan", target, "--format", "bad"])
    assert invalid_format.exit_code == 2

    invalid_fail_on = runner.invoke(app, ["scan", target, "--fail-on", "bad"])
    assert invalid_fail_on.exit_code == 2

    invalid_intel_age = runner.invoke(app, ["scan", target, "--intel-max-age-minutes", "0"])
    assert invalid_intel_age.exit_code == 2


def test_scan_fail_on_warn_and_block() -> None:
    warn_result = runner.invoke(
        app,
        [
            "scan",
            "examples/showcase/08_unpinned_deps",
            "--no-auto-intel",
            "--fail-on",
            "warn",
        ],
    )
    assert warn_result.exit_code == 1

    block_result = runner.invoke(
        app,
        [
            "scan",
            "examples/showcase/01_download_execute",
            "--no-auto-intel",
            "--fail-on",
            "block",
        ],
    )
    assert block_result.exit_code == 1


def test_scan_json_stdout_and_auto_intel_message(monkeypatch) -> None:
    monkeypatch.setattr(
        "skillscan.cli.sync_managed",
        lambda **_kwargs: {"updated": 1, "skipped": 0, "errors": 0},
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "tests/fixtures/benign/basic_skill",
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
    )
    assert result.exit_code == 0
    assert "intel refresh" in result.stdout
    start = result.stdout.find("{")
    parsed = json.loads(result.stdout[start:])
    assert parsed["metadata"]["target"].endswith("basic_skill")


def test_intel_subcommands(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SKILLSCAN_HOME", str(tmp_path / ".skillscan"))
    sample = tmp_path / "sample.json"
    sample.write_text(json.dumps({"domains": ["z.com"], "ips": [], "urls": []}), encoding="utf-8")

    add = runner.invoke(app, ["intel", "add", str(sample), "--type", "ioc", "--name", "local"])
    assert add.exit_code == 0

    status = runner.invoke(app, ["intel", "status"])
    assert status.exit_code == 0
    assert "Sources: 1" in status.stdout

    listing = runner.invoke(app, ["intel", "list"])
    assert listing.exit_code == 0
    assert "local" in listing.stdout

    disable = runner.invoke(app, ["intel", "disable", "local"])
    assert disable.exit_code == 0

    enable = runner.invoke(app, ["intel", "enable", "local"])
    assert enable.exit_code == 0

    rebuild = runner.invoke(app, ["intel", "rebuild"])
    assert rebuild.exit_code == 0

    sync = runner.invoke(app, ["intel", "sync", "--max-age-minutes", "0"])
    assert sync.exit_code == 2

    monkeypatch.setattr(
        "skillscan.cli.sync_managed",
        lambda **_kwargs: {"updated": 0, "skipped": 1, "errors": 0},
    )
    sync_ok = runner.invoke(app, ["intel", "sync"])
    assert sync_ok.exit_code == 0
    assert "Managed intel sync complete" in sync_ok.stdout

    remove = runner.invoke(app, ["intel", "remove", "local"])
    assert remove.exit_code == 0

    remove_missing = runner.invoke(app, ["intel", "remove", "missing"])
    assert remove_missing.exit_code == 1


def test_policy_validate_and_uninstall(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SKILLSCAN_HOME", str(tmp_path / ".skillscan"))
    policy = tmp_path / "p.yaml"
    policy.write_text(
        """
name: custom
description: custom
thresholds:
  warn: 10
  block: 20
weights:
  malware_pattern: 1
hard_block_rules: []
allow_domains: []
block_domains: []
limits:
  max_files: 100
  max_depth: 3
  max_bytes: 100000
  timeout_seconds: 10
""".strip(),
        encoding="utf-8",
    )

    validate = runner.invoke(app, ["policy", "validate", str(policy)])
    assert validate.exit_code == 0

    bin_dir = tmp_path / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    (bin_dir / "skillscan").write_text("x", encoding="utf-8")

    keep = runner.invoke(app, ["uninstall", "--keep-data"])
    assert keep.exit_code == 0

    no_keep = runner.invoke(app, ["uninstall"])
    assert no_keep.exit_code == 0
