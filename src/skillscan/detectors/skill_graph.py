"""Skill graph analyzer — detects cross-skill invocation abuse, remote .md loading,
and memory-file poisoning patterns.

Rule IDs emitted:
  PINJ-GRAPH-001  Skill loads a remote Markdown file at runtime
  PINJ-GRAPH-002  Skill grants a high-risk tool without a declared purpose
  PINJ-GRAPH-003  Skill instructs the agent to write a memory/config file
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml  # type: ignore[import-untyped]

from skillscan.models import Finding, Severity

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Remote .md fetch: URL ending in .md (optionally with query/fragment)
_REMOTE_MD_RE = re.compile(
    r"https?://[^\s\"'<>)]+\.md(?:[?#][^\s\"'<>)]*)?",
    re.IGNORECASE,
)

# Tool calls that fetch remote content and could load a .md
_FETCH_TOOL_RE = re.compile(
    r"\b(?:fetch|curl|wget|http_get|url_fetch|web_fetch|read_url|get_url)\b",
    re.IGNORECASE,
)

# High-risk tools that grant code execution or full computer control
_HIGH_RISK_TOOLS = frozenset(
    {
        "bash",
        "computer",
        "computer_use",
        "shell",
        "terminal",
        "execute_code",
        "run_code",
        "code_execution",
        "exec",
    }
)

# Memory / config files that, if written, affect all future agent sessions
_MEMORY_FILES = frozenset(
    {
        "soul.md",
        "memory.md",
        "agents.md",
        "claude.md",
        ".claude/settings.json",
        "settings.json",
        "agent.md",
        "system.md",
        "context.md",
    }
)

# Patterns that indicate a write/modify instruction in prose
_WRITE_INSTRUCTION_RE = re.compile(
    r"\b(?:write|update|modify|append|overwrite|save|edit|create|patch)\b"
    r"[^.]{0,80}"
    r"(?:soul\.md|memory\.md|agents\.md|claude\.md|settings\.json|agent\.md|system\.md)",
    re.IGNORECASE,
)

# Skill reference: "use skill X", "invoke skill X", "load skill X", "/skill-name"
_SKILL_REF_RE = re.compile(
    r"(?:use|invoke|load|run|call|activate)\s+(?:skill\s+)?[\"']?([a-z0-9_-]{3,50})[\"']?"
    r"|/([a-z0-9_-]{3,50})\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class SkillNode:
    """Parsed representation of a single SKILL.md file."""

    path: Path
    name: str
    description: str
    allowed_tools: list[str] = field(default_factory=list)
    context: str = ""
    body: str = ""
    raw_front_matter: dict = field(default_factory=dict)


@dataclass
class SkillGraph:
    nodes: dict[str, SkillNode] = field(default_factory=dict)  # name → node
    # Edges: (source_name, target_name, edge_type)
    edges: list[tuple[str, str, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_skill_file(path: Path) -> SkillNode | None:
    """Parse a SKILL.md file into a SkillNode.  Returns None on parse failure."""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    front_matter: dict = {}
    body = raw

    # Extract YAML front-matter (--- ... ---)
    if raw.startswith("---"):
        end = raw.find("\n---", 3)
        if end != -1:
            fm_text = raw[3:end].strip()
            body = raw[end + 4 :].strip()
            try:
                parsed = yaml.safe_load(fm_text)
                if isinstance(parsed, dict):
                    front_matter = parsed
            except yaml.YAMLError:
                pass

    name = str(front_matter.get("name", path.parent.name))
    description = str(front_matter.get("description", ""))
    raw_tools = front_matter.get("allowed-tools", front_matter.get("allowed_tools", []))
    if isinstance(raw_tools, str):
        allowed_tools = [t.strip() for t in raw_tools.split(",") if t.strip()]
    elif isinstance(raw_tools, list):
        allowed_tools = [str(t).strip() for t in raw_tools]
    else:
        allowed_tools = []

    context = str(front_matter.get("context", ""))

    return SkillNode(
        path=path,
        name=name,
        description=description,
        allowed_tools=allowed_tools,
        context=context,
        body=body,
        raw_front_matter=front_matter,
    )


def build_skill_graph(root: Path) -> SkillGraph:
    """Walk *root* and build a SkillGraph from all SKILL.md files found."""
    graph = SkillGraph()

    for skill_path in sorted(root.rglob("SKILL.md")):
        node = _parse_skill_file(skill_path)
        if node is None:
            continue
        # Deduplicate by path if the same name appears twice
        key = str(skill_path)
        graph.nodes[key] = node

    # Build edges: skill references in body text
    node_names = {n.name.lower() for n in graph.nodes.values()}
    for key, node in graph.nodes.items():
        for m in _SKILL_REF_RE.finditer(node.body):
            ref_name = (m.group(1) or m.group(2) or "").lower()
            if ref_name and ref_name in node_names and ref_name != node.name.lower():
                graph.edges.append((node.name, ref_name, "invokes"))

    return graph


# ---------------------------------------------------------------------------
# Rule detectors
# ---------------------------------------------------------------------------


def _check_remote_md_load(node: SkillNode) -> list[Finding]:
    """PINJ-GRAPH-001: skill body references a remote .md URL."""
    findings: list[Finding] = []
    full_text = node.description + "\n" + node.body

    # Case 1: explicit remote .md URL
    for m in _REMOTE_MD_RE.finditer(full_text):
        url = m.group(0)
        line_no = full_text[: m.start()].count("\n") + 1
        findings.append(
            Finding(
                id="PINJ-GRAPH-001",
                category="prompt_injection",
                severity=Severity.HIGH,
                confidence=0.88,
                title="Skill loads remote Markdown at runtime",
                evidence_path=str(node.path),
                line=line_no,
                snippet=url[:240],
                mitigation=(
                    "Remote .md files loaded at runtime can contain adversarial instructions. "
                    "Pin skill content locally or verify remote sources with a content hash."
                ),
            )
        )
        break  # one finding per skill is enough

    # Case 2: fetch-tool call present but no explicit .md URL — lower confidence
    if not findings and _FETCH_TOOL_RE.search(full_text):
        # Only flag if the body also mentions a URL-like pattern (http/https)
        if re.search(r"https?://", full_text, re.IGNORECASE):
            findings.append(
                Finding(
                    id="PINJ-GRAPH-001",
                    category="prompt_injection",
                    severity=Severity.MEDIUM,
                    confidence=0.60,
                    title="Skill may load remote content via fetch tool",
                    evidence_path=str(node.path),
                    snippet="fetch/curl/wget with remote URL detected",
                    mitigation=(
                        "Skill uses a network fetch tool alongside a remote URL. "
                        "Verify the fetched content cannot contain adversarial instructions."
                    ),
                )
            )

    return findings


def _check_tool_grant_without_purpose(node: SkillNode) -> list[Finding]:
    """PINJ-GRAPH-002: skill grants a high-risk tool but the body lacks a clear purpose."""
    findings: list[Finding] = []
    granted = [t.lower() for t in node.allowed_tools if t.lower() in _HIGH_RISK_TOOLS]
    if not granted:
        return findings

    # A "declared purpose" is at least one of: a ## Usage / ## Purpose / ## When to use section,
    # or a sentence of >= 20 words in the body that explains what the tool does.
    _purpose_re = re.compile(
        r"^#{1,3}\s*(usage|purpose|when to use|overview|description)",
        re.IGNORECASE | re.MULTILINE,
    )
    has_purpose_section = bool(_purpose_re.search(node.body))
    # Count meaningful body words (strip YAML artifacts)
    word_count = len(node.body.split())
    has_sufficient_body = word_count >= 30

    if not has_purpose_section and not has_sufficient_body:
        findings.append(
            Finding(
                id="PINJ-GRAPH-002",
                category="prompt_injection",
                severity=Severity.MEDIUM,
                confidence=0.72,
                title=f"High-risk tool granted without declared purpose: {', '.join(granted)}",
                evidence_path=str(node.path),
                snippet=f"allowed-tools: {', '.join(node.allowed_tools)}",
                mitigation=(
                    "Skills that grant Bash/Computer/Shell access should include a clear "
                    "## Usage or ## Purpose section explaining the intended use. "
                    "Undocumented tool grants are a common indicator of malicious skills."
                ),
            )
        )

    return findings


def _check_memory_write(node: SkillNode) -> list[Finding]:
    """PINJ-GRAPH-003: skill instructs agent to write a memory/config file."""
    findings: list[Finding] = []
    full_text = node.description + "\n" + node.body

    # Pattern 1: explicit write instruction mentioning a known memory file
    m = _WRITE_INSTRUCTION_RE.search(full_text)
    if m:
        line_no = full_text[: m.start()].count("\n") + 1
        findings.append(
            Finding(
                id="PINJ-GRAPH-003",
                category="prompt_injection",
                severity=Severity.CRITICAL,
                confidence=0.90,
                title="Skill instructs agent to write a memory/config file",
                evidence_path=str(node.path),
                line=line_no,
                snippet=m.group(0)[:240],
                mitigation=(
                    "Writing to SOUL.md, MEMORY.md, AGENTS.md, or settings files persists "
                    "instructions across all future agent sessions. "
                    "This is a high-confidence memory-poisoning indicator. "
                    "Remove the skill and audit any affected memory files."
                ),
            )
        )
        return findings  # one finding per skill

    # Pattern 2: memory file name appears in body without explicit write verb — lower confidence
    for mem_file in _MEMORY_FILES:
        if mem_file in full_text.lower():
            # Only flag if there's also an action verb nearby
            pattern = re.compile(
                r"\b(?:update|modify|append|overwrite|save|edit|create|patch|write)\b"
                r"[^.]{0,120}"
                + re.escape(mem_file),
                re.IGNORECASE,
            )
            m2 = pattern.search(full_text.lower())
            if m2:
                line_no = full_text.lower()[: m2.start()].count("\n") + 1
                findings.append(
                    Finding(
                        id="PINJ-GRAPH-003",
                        category="prompt_injection",
                        severity=Severity.HIGH,
                        confidence=0.75,
                        title=f"Skill references memory file with write intent: {mem_file}",
                        evidence_path=str(node.path),
                        line=line_no,
                        snippet=m2.group(0)[:240],
                        mitigation=(
                            "Skill references a memory/config file alongside a write-intent verb. "
                            "Verify this is intentional and the skill is from a trusted source."
                        ),
                    )
                )
                break

    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def skill_graph_findings(root: Path) -> list[Finding]:
    """Build the skill graph for *root* and return all graph-level findings."""
    graph = build_skill_graph(root)
    findings: list[Finding] = []

    for node in graph.nodes.values():
        findings.extend(_check_remote_md_load(node))
        findings.extend(_check_tool_grant_without_purpose(node))
        findings.extend(_check_memory_write(node))

    return findings
