from __future__ import annotations

from skillscan.detectors.ast_flows import load_compiled_ast_flow_config
from skillscan.rules import load_builtin_rulepack, load_compiled_builtin_rulepack


def test_builtin_rulepack_loads() -> None:
    rp = load_builtin_rulepack()
    assert rp.version
    assert len(rp.static_rules) >= 4
    assert "download" in rp.action_patterns
    assert len(rp.chain_rules) >= 3


def test_compiled_rulepack_contains_patterns() -> None:
    compiled = load_compiled_builtin_rulepack()
    assert compiled.version
    assert compiled.static_rules
    assert compiled.chain_rules
    assert compiled.capability_patterns
    assert compiled.static_rules[0].pattern.search("curl x | bash") is not None


def test_ast_flow_config_loads() -> None:
    cfg = load_compiled_ast_flow_config()
    assert cfg.version
    assert "os.getenv" in cfg.secret_source_calls
    assert "eval" in cfg.exec_sink_calls
    assert "AST-001" in cfg.rules_by_id
