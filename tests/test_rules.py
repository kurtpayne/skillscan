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


def test_new_patterns_2026_02_09() -> None:
    """Test new patterns added from Feb 2026 dYdX supply chain attack."""
    compiled = load_compiled_builtin_rulepack()
    
    # EXF-002: Crypto wallet file access
    exf002 = next((r for r in compiled.static_rules if r.id == "EXF-002"), None)
    assert exf002 is not None
    assert exf002.pattern.search("wallet.dat") is not None
    assert exf002.pattern.search(".keystore") is not None
    assert exf002.pattern.search("mnemonic") is not None
    
    # MAL-004: Dynamic code evaluation
    mal004 = next((r for r in compiled.static_rules if r.id == "MAL-004"), None)
    assert mal004 is not None
    assert mal004.pattern.search("eval(code)") is not None
    assert mal004.pattern.search("exec(payload)") is not None
    assert mal004.pattern.search("Function('return x')") is not None
    
    # OBF-002: Stealth execution patterns
    obf002 = next((r for r in compiled.static_rules if r.id == "OBF-002"), None)
    assert obf002 is not None
    assert obf002.pattern.search("CREATE_NO_WINDOW") is not None
    assert obf002.pattern.search("nohup cmd >/dev/null") is not None
