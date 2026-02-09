from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, Field

from skillscan.models import Severity


class StaticRule(BaseModel):
    id: str
    category: str
    severity: Severity
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    title: str
    pattern: str
    mitigation: str | None = None


class ChainRule(BaseModel):
    id: str
    category: str
    severity: Severity
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    title: str
    all_of: list[str]
    snippet: str = ""
    mitigation: str | None = None


class RulePack(BaseModel):
    version: str
    static_rules: list[StaticRule] = Field(default_factory=list)
    action_patterns: dict[str, str] = Field(default_factory=dict)
    chain_rules: list[ChainRule] = Field(default_factory=list)
    capability_patterns: dict[str, str] = Field(default_factory=dict)


@dataclass
class CompiledStaticRule:
    id: str
    category: str
    severity: Severity
    confidence: float
    title: str
    pattern: re.Pattern[str]
    mitigation: str | None


@dataclass
class CompiledChainRule:
    id: str
    category: str
    severity: Severity
    confidence: float
    title: str
    all_of: set[str]
    snippet: str
    mitigation: str | None


@dataclass
class CompiledRulePack:
    version: str
    static_rules: list[CompiledStaticRule]
    action_patterns: dict[str, re.Pattern[str]]
    chain_rules: list[CompiledChainRule]
    capability_patterns: list[tuple[str, re.Pattern[str]]]


def _merge_rulepacks(rulepacks: list[RulePack]) -> RulePack:
    static_rules: list[StaticRule] = []
    chain_rules: list[ChainRule] = []
    action_patterns: dict[str, str] = {}
    capability_patterns: dict[str, str] = {}
    versions: list[str] = []

    for rp in rulepacks:
        versions.append(rp.version)
        static_rules.extend(rp.static_rules)
        chain_rules.extend(rp.chain_rules)
        action_patterns.update(rp.action_patterns)
        capability_patterns.update(rp.capability_patterns)

    return RulePack(
        version="+".join(versions),
        static_rules=static_rules,
        action_patterns=action_patterns,
        chain_rules=chain_rules,
        capability_patterns=capability_patterns,
    )


def _load_yaml_rule_file(raw: str) -> RulePack:
    parsed = yaml.safe_load(raw)
    return RulePack.model_validate(parsed)


def load_builtin_rulepack() -> RulePack:
    rules_dir = resources.files("skillscan.data.rules")
    files = sorted([p for p in rules_dir.iterdir() if p.name.endswith(".yaml")], key=lambda p: p.name)
    rulepacks = [_load_yaml_rule_file(p.read_text(encoding="utf-8")) for p in files]
    return _merge_rulepacks(rulepacks)


@lru_cache(maxsize=1)
def load_compiled_builtin_rulepack() -> CompiledRulePack:
    rp = load_builtin_rulepack()
    static_rules = [
        CompiledStaticRule(
            id=r.id,
            category=r.category,
            severity=r.severity,
            confidence=r.confidence,
            title=r.title,
            pattern=re.compile(r.pattern, re.IGNORECASE),
            mitigation=r.mitigation,
        )
        for r in rp.static_rules
    ]
    action_patterns = {
        name: re.compile(pattern, re.IGNORECASE) for name, pattern in rp.action_patterns.items()
    }
    chain_rules = [
        CompiledChainRule(
            id=r.id,
            category=r.category,
            severity=r.severity,
            confidence=r.confidence,
            title=r.title,
            all_of=set(r.all_of),
            snippet=r.snippet,
            mitigation=r.mitigation,
        )
        for r in rp.chain_rules
    ]
    capability_patterns = [
        (name, re.compile(pattern, re.IGNORECASE)) for name, pattern in rp.capability_patterns.items()
    ]
    return CompiledRulePack(
        version=rp.version,
        static_rules=static_rules,
        action_patterns=action_patterns,
        chain_rules=chain_rules,
        capability_patterns=capability_patterns,
    )
