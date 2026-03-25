"""
Pytest configuration for skillscan-security test suite.

Root cause of the test pollution problem:
  The scan command calls maybe_sync_rules() which downloads default.yaml from
  the *main* branch of the repo.  When running tests on a PR branch the
  installed package has the PR's rules, but the auto-sync overwrites
  ~/.skillscan/rules/default.yaml with main's version.  Because
  load_builtin_rulepack() merges bundled + user-local rules with "last writer
  wins" semantics, the user-local (main) copy wins and PR-branch rule changes
  are invisible to the test suite.

Fix applied here:
  1. Remove ~/.skillscan/rules/ at session start so no stale user-local rules
     exist before any test runs.
  2. Monkeypatch maybe_sync_rules() to a no-op for the entire session so that
     tests which exercise the full scan() path cannot re-download from main.
  3. Clear the load_compiled_builtin_rulepack() LRU cache after setup so all
     tests start with a fresh load from the bundled (installed) rules only.
"""
from __future__ import annotations

import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from skillscan.rules_sync import RuleSyncResult


@pytest.fixture(autouse=True, scope="session")
def _isolate_user_rules() -> None:  # type: ignore[return]
    """
    Ensure tests always use the bundled (installed) rules, not any user-local
    rules that may have been downloaded from the main branch.
    """
    # 1. Remove any existing user-local rules dir
    user_rules_dir = Path.home() / ".skillscan" / "rules"
    if user_rules_dir.exists():
        shutil.rmtree(user_rules_dir)

    # 2. Patch maybe_sync_rules to a no-op for the whole session
    with patch(
        "skillscan.rules_sync.maybe_sync_rules",
        return_value=RuleSyncResult(skipped=["default.yaml"], from_cache=True),
    ):
        # 3. Clear the LRU cache so the first test gets a fresh load
        from skillscan.rules import load_compiled_builtin_rulepack
        load_compiled_builtin_rulepack.cache_clear()

        yield  # run all tests

        # 4. Clear cache again on teardown for hygiene
        load_compiled_builtin_rulepack.cache_clear()
