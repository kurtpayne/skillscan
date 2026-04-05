# analysis/_sections.py — Markdown section classifier for context-aware scoring.
#
# Parses the heading structure of a SKILL.md file and assigns a score multiplier
# to each line based on which section it falls under.  Rules that fire in a
# "Security Notes" or "Examples" section should score lower than the same rule
# firing in an "Instructions" or "Usage" section.
#
# Multiplier table:
#   instruction   (Setup, Usage, Instructions, Steps, Configuration…)  → 1.0×
#   example       (Examples, Sample, Demo, Test…)                       → 0.4×
#   documentation (Security, Notes, References, About, Privacy…)        → 0.15×
#   unknown       (anything else)                                        → 0.7×
#   preamble      (lines before the first heading)                       → 0.7×
from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["SectionMap", "build_section_map"]

# ---------------------------------------------------------------------------
# Section classification rules
# Each entry is (compiled regex, multiplier).  First match wins.
# ---------------------------------------------------------------------------
_SECTION_RULES: list[tuple[re.Pattern[str], float]] = [
    # ── Instruction sections (full weight) ──────────────────────────────────
    (re.compile(r"\b(setup|install|installation|usage|use|using|how.?to|instructions?|steps?|"
                r"getting.?started|quick.?start|configure|configuration|run|running|"
                r"deploy|deployment|execution|workflow|procedure|implementation)\b",
                re.IGNORECASE), 1.0),
    # ── Example / test sections (low weight) ────────────────────────────────
    (re.compile(r"\b(examples?|samples?|demo|demos|test|testing|trial|walkthrough|"
                r"showcase|illustration|scenario)\b",
                re.IGNORECASE), 0.4),
    # ── Documentation / background sections (very low weight) ───────────────
    (re.compile(r"\b(security|note[s]?|warning[s]?|caution|notice|disclaimer|"
                r"reference[s]?|resource[s]?|background|about|overview|introduction|"
                r"motivation|rationale|philosophy|prior.?art|related.?work|"
                r"privac[y]?|license|licen[sc]ing|legal|terms|compliance|"
                r"troubleshoot|faq|known.?issues?|limitations?|caveats?|"
                r"changelog|history|release|migration|upgrade|deprecat)\b",
                re.IGNORECASE), 0.15),
]

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+)$")
_DEFAULT_MULTIPLIER = 0.7    # unknown/ambiguous section (headings present but unclassified)
_PREAMBLE_MULTIPLIER = 1.0   # lines before the first heading: unstructured = assume instruction context
_NO_HEADINGS_MULTIPLIER = 1.0  # whole-file multiplier when no headings exist at all


@dataclass(frozen=True)
class SectionSpan:
    start_line: int   # 1-based, inclusive
    end_line: int     # 1-based, inclusive (or sys.maxsize for the last section)
    heading: str      # normalised heading text (empty string for preamble)
    multiplier: float


_FENCE_CODE_MODIFIER = 0.5  # applied on top of section multiplier for lines inside a code fence


@dataclass
class SectionMap:
    """Maps line numbers to section score multipliers.

    All line numbers are 1-based to match the convention used by the scanner.
    The multiplier returned is the product of the *section* multiplier and,
    for lines inside a code fence, an additional *fence* modifier (0.5×).

    Example: a rule firing on line 42 in a "Security Notes" section (0.15×)
    inside a code fence returns 0.15 × 0.5 = 0.075.  A rule firing in a
    "Setup" section (1.0×) inside a code fence returns 1.0 × 0.5 = 0.5.
    """

    _spans: list[SectionSpan]
    _fence_lines: frozenset[int]  # 1-based line numbers inside a code fence

    def multiplier(self, line_no: int) -> float:
        """Return the score multiplier for *line_no* (1-based)."""
        section_mult = _DEFAULT_MULTIPLIER
        for span in self._spans:
            if span.start_line <= line_no <= span.end_line:
                section_mult = span.multiplier
                break
        fence_mod = _FENCE_CODE_MODIFIER if line_no in self._fence_lines else 1.0
        return section_mult * fence_mod

    def section_name(self, line_no: int) -> str:
        """Return the heading text for the section containing *line_no*."""
        for span in self._spans:
            if span.start_line <= line_no <= span.end_line:
                return span.heading
        return ""

    def in_code_fence(self, line_no: int) -> bool:
        return line_no in self._fence_lines


def _classify_heading(heading: str) -> float:
    """Return a score multiplier for the given heading text."""
    for pattern, mult in _SECTION_RULES:
        if pattern.search(heading):
            return mult
    return _DEFAULT_MULTIPLIER


def build_section_map(text: str) -> SectionMap:
    """Parse *text* and return a :class:`SectionMap`.

    Only top-level and second-level headings (H1/H2) are used for section
    classification.  Deeper headings inherit their parent section's multiplier.
    Heading content inside code fences is ignored.  Lines inside code fences
    receive an additional 0.5× modifier on top of their section multiplier.
    """
    lines = text.splitlines()
    total = len(lines)

    # First pass: locate code fence boundaries.
    fence_lines: set[int] = set()
    in_fence = False
    fence_start = 0
    for idx, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            if in_fence:
                in_fence = False
                # Mark interior lines (not the delimiter lines themselves)
                for fence_line in range(fence_start + 1, idx):
                    fence_lines.add(fence_line)
            else:
                in_fence = True
                fence_start = idx

    # Locate section boundaries, skipping headings inside fenced code blocks.
    section_starts: list[tuple[int, str, float]] = []  # (1-based line, heading text, multiplier)

    for idx, raw in enumerate(lines, 1):
        if idx in fence_lines:
            continue
        m = _HEADING_RE.match(raw)
        if m:
            level = len(m.group(1))
            heading_text = m.group(2).strip()
            if level <= 2:
                # Only H1/H2 create new sections; H3+ inherit parent
                mult = _classify_heading(heading_text)
                section_starts.append((idx, heading_text, mult))

    # Build spans from section starts
    spans: list[SectionSpan] = []
    if not section_starts:
        # No headings at all — treat the whole file as unknown
        spans.append(SectionSpan(1, total or 1, "", _NO_HEADINGS_MULTIPLIER))
        return SectionMap(_spans=spans, _fence_lines=frozenset(fence_lines))

    first_heading_line = section_starts[0][0]
    if first_heading_line > 1:
        # Preamble (YAML frontmatter, title block, etc.)
        spans.append(SectionSpan(1, first_heading_line - 1, "", _PREAMBLE_MULTIPLIER))

    for i, (start, heading, mult) in enumerate(section_starts):
        end = section_starts[i + 1][0] - 1 if i + 1 < len(section_starts) else total
        spans.append(SectionSpan(start, end, heading, mult))

    return SectionMap(_spans=spans, _fence_lines=frozenset(fence_lines))
