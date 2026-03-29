"""ml_detector.py — Offline HuggingFace-based prompt-injection detector.

Uses protectai/deberta-v3-base-prompt-injection-v2 (Apache 2.0) for high-accuracy
ML-based detection as an optional complement to the deterministic rule engine.

The model is loaded lazily on first call and cached in-process.  Two backends
are supported, selected automatically based on what is installed:

  1. ONNX Runtime (preferred, CPU-only, ~200 MB)
       pip install skillscan-security[ml-onnx]
       requires: optimum[onnxruntime], transformers

  2. PyTorch / Transformers (fallback, ~500 MB)
       pip install skillscan-security[ml]
       requires: transformers, torch

If neither backend is available the detector is silently skipped and an
informational Finding is emitted so the user knows to install the extras.

Model: protectai/deberta-v3-base-prompt-injection-v2
  - Fine-tuned DeBERTa-v3-base for binary prompt-injection classification
  - Labels: 0 = SAFE, 1 = INJECTION
  - Post-training accuracy: 95.25 % (20 k held-out prompts)
  - License: Apache 2.0
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from skillscan.models import Finding, Severity

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

_MODEL_ID = "ProtectAI/deberta-v3-base-prompt-injection-v2"
_MAX_LENGTH = 512
_INJECTION_THRESHOLD = 0.70  # minimum score for INJECTION label to fire
_HIGH_THRESHOLD = 0.88  # score above this → HIGH severity, else MEDIUM

# ---------------------------------------------------------------------------
# Lazy singleton cache
# ---------------------------------------------------------------------------
_pipeline_cache: Any = None
_backend_cache: str | None = None  # "onnx" | "transformers" | "unavailable"


def _try_load_onnx() -> Any | None:
    """Attempt to load the ONNX Runtime backend via 🤗 Optimum."""
    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification  # type: ignore[import]
        from transformers import AutoTokenizer, pipeline  # type: ignore[import]

        tokenizer = AutoTokenizer.from_pretrained(_MODEL_ID, subfolder="onnx")
        tokenizer.model_input_names = ["input_ids", "attention_mask"]
        model = ORTModelForSequenceClassification.from_pretrained(_MODEL_ID, export=False, subfolder="onnx")
        return pipeline(
            task="text-classification",
            model=model,
            tokenizer=tokenizer,
            truncation=True,
            max_length=_MAX_LENGTH,
        )
    except Exception as exc:
        logger.debug("ONNX backend unavailable: %s", exc)
        return None


def _try_load_transformers() -> Any | None:
    """Attempt to load the PyTorch / Transformers backend."""
    try:
        import torch  # type: ignore[import]
        from transformers import (  # type: ignore[import]
            AutoModelForSequenceClassification,
            AutoTokenizer,
            pipeline,
        )

        tokenizer = AutoTokenizer.from_pretrained(_MODEL_ID)
        model = AutoModelForSequenceClassification.from_pretrained(_MODEL_ID)
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        return pipeline(
            "text-classification",
            model=model,
            tokenizer=tokenizer,
            truncation=True,
            max_length=_MAX_LENGTH,
            device=device,
        )
    except Exception as exc:
        logger.debug("Transformers backend unavailable: %s", exc)
        return None


def _get_pipeline() -> tuple[Any | None, str]:
    """Return (pipeline, backend_name).  Results are cached after first call."""
    global _pipeline_cache, _backend_cache
    if _backend_cache is not None:
        return _pipeline_cache, _backend_cache

    pipe = _try_load_onnx()
    if pipe is not None:
        _pipeline_cache, _backend_cache = pipe, "onnx"
        logger.info("ML detector: loaded ONNX backend (%s)", _MODEL_ID)
        return pipe, "onnx"

    pipe = _try_load_transformers()
    if pipe is not None:
        _pipeline_cache, _backend_cache = pipe, "transformers"
        logger.info("ML detector: loaded Transformers backend (%s)", _MODEL_ID)
        return pipe, "transformers"

    _pipeline_cache, _backend_cache = None, "unavailable"
    logger.warning(
        "ML detector: neither optimum[onnxruntime] nor transformers+torch is installed. "
        "Install skillscan-security[ml-onnx] or skillscan-security[ml] to enable."
    )
    return None, "unavailable"


# ---------------------------------------------------------------------------
# Text chunking helpers
# ---------------------------------------------------------------------------

_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def _chunk_text(text: str, max_chars: int = 1800) -> list[str]:
    """Split *text* into chunks of at most *max_chars* characters.

    Splitting on sentence boundaries where possible keeps semantic context
    intact and avoids truncating mid-sentence.
    """
    if len(text) <= max_chars:
        return [text]

    sentences = _SENTENCE_SPLIT_RE.split(text)
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0

    for sent in sentences:
        if current_len + len(sent) > max_chars and current:
            chunks.append(" ".join(current))
            current, current_len = [], 0
        current.append(sent)
        current_len += len(sent) + 1

    if current:
        chunks.append(" ".join(current))

    return chunks or [text[:max_chars]]


# ---------------------------------------------------------------------------
# M10.8 — Attack-type hint classifier (keyword post-processor)
# ---------------------------------------------------------------------------

# Priority-ordered list of (hint_label, compiled_pattern) tuples.
# Evaluated top-to-bottom; first match wins.
_ATTACK_HINT_RULES: list[tuple[str, re.Pattern[str]]] = [
    (
        "exfiltration",
        re.compile(
            r"(?i)"
            r"(?:dns|webhook|exfil|curl\s|wget\s|http[s]?://[^\s]{10,}|base64|b64encode"
            r"|send.*secret|leak.*token|POST.*cred|exfiltrat|steal.*key"
            r"|error.*message.*token|\bngrok\b|\bburp\b|\binteract\.sh\b)"
        ),
    ),
    (
        "supply_chain",
        re.compile(
            r"(?i)"
            r"(?:setup\.py|__init__.*exec|pip install.*&&|npm install.*&&"
            r"|postinstall|preinstall|install_requires.*subprocess"
            r"|package.*hook|dependency.*inject|malicious.*package"
            r"|typosquat|\bpypi\b.*malware|\bnpm\b.*malware)"
        ),
    ),
    (
        "jailbreak",
        re.compile(
            r"(?i)"
            r"(?:developer mode|DAN|do anything now|jailbreak"
            r"|ignore (?:previous|all|your|prior) (?:instructions?|rules?|constraints?|guidelines?)"
            r"|pretend you (?:are|have no|can)"
            r"|you are now|act as (?:an? )?(?:AI|assistant|bot|GPT|Claude) (?:without|with no)"
            r"|unrestricted (?:mode|AI|assistant)"
            r"|no (?:restrictions?|limits?|filters?|safety|guidelines?)"
            r"|bypass (?:safety|filter|restriction|guideline)"
            r"|\bDAN\b|\bDANmode\b)"
        ),
    ),
    (
        "indirect_injection",
        re.compile(
            r"(?i)"
            r"(?:when you (?:read|see|encounter|process)"
            r"|if (?:this|the following) (?:appears?|is (?:read|seen|processed))"
            r"|hidden (?:in|within) (?:the )?(?:rss|feed|changelog|result|output|response)"
            r"|tool (?:result|output|response).*inject"
            r"|\brss\b.*inject|\bchangelog\b.*inject"
            r"|embedded (?:in|within) (?:the )?(?:document|page|result)"
            r"|\brag\b.*inject|retrieval.*inject)"
        ),
    ),
    (
        "social_engineering",
        re.compile(
            r"(?i)"
            r"(?:urgent(?:ly)?|immediately|your (?:account|access|token|key|credential)"
            r"|verify your|confirm (?:your )?(?:identity|credentials?|account)"
            r"|deprecated (?:api|token|key|endpoint)"
            r"|(?:prize|reward|winner|congratulations|you.?ve won)"
            r"|vendor (?:support|update|notice|alert)"
            r"|security (?:alert|warning|notice|update) (?:from|by) (?:anthropic|openai|manus)"
            r"|click (?:here|this link)|limited time)"
        ),
    ),
    (
        "prompt_injection",
        re.compile(
            r"(?i)"
            r"(?:ignore (?:the )?(?:system|previous|above|prior)"
            r"|override (?:the )?(?:system|previous|above|prior)"
            r"|disregard (?:the )?(?:system|previous|above|prior)"
            r"|forget (?:the )?(?:system|previous|above|prior)"
            r"|your (?:new |real |actual )?(?:instructions?|goal|task|objective|purpose) (?:is|are)"
            r"|new (?:instructions?|goal|task|objective|purpose):"
            r"|system prompt|context (?:window|extract|leak)"
            r"|reveal (?:your|the) (?:system|instructions?|prompt)"
            r"|what (?:are|were) your (?:instructions?|system prompt)"
            r"|role (?:override|hijack|switch)"
            r"|\[SYSTEM\]|\[INST\]|<\|system\|>|<\|im_start\|>)"
        ),
    ),
]


def _classify_attack_type(text: str) -> str | None:
    """Return the most likely attack-type hint for *text*, or None.

    Applies a priority-ordered keyword ruleset.  The first matching rule wins.
    Returns one of: 'exfiltration', 'supply_chain', 'jailbreak',
    'indirect_injection', 'social_engineering', 'prompt_injection', or None.
    """
    for hint, pattern in _ATTACK_HINT_RULES:
        if pattern.search(text):
            return hint
    return None


_ATTACK_HINT_MITIGATIONS: dict[str, str] = {
    "exfiltration": (
        "This skill appears to contain data-exfiltration patterns: DNS callbacks, webhook URLs, "
        "or commands that send secrets/tokens to external endpoints. "
        "Audit all network calls and remove any that transmit sensitive data."
    ),
    "supply_chain": (
        "This skill contains supply-chain injection patterns: malicious package hooks, "
        "postinstall scripts, or dependency manipulation. "
        "Verify all package names against known-good registries and audit install scripts."
    ),
    "jailbreak": (
        "This skill contains jailbreak language: instructions to enter 'developer mode', "
        "act as an unrestricted AI, or ignore safety guidelines. "
        "Remove override/bypass instructions and ensure the skill does not attempt to "
        "circumvent model safety constraints."
    ),
    "indirect_injection": (
        "This skill contains indirect-injection patterns: instructions that activate when "
        "the model reads external content (RSS feeds, changelogs, tool results). "
        "Sanitize all external content before passing it to the model context."
    ),
    "social_engineering": (
        "This skill contains social-engineering language: urgency cues, credential-verification "
        "requests, prize/reward lures, or impersonation of trusted vendors. "
        "Remove manipulative language and ensure the skill does not coerce users into "
        "disclosing credentials or clicking untrusted links."
    ),
    "prompt_injection": (
        "This skill contains prompt-injection patterns: instructions to override the system "
        "prompt, extract context, or hijack the model's goal. "
        "Remove role-override and context-extraction instructions."
    ),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Large-file thresholds (13e)
# ---------------------------------------------------------------------------

_LARGE_FILE_LINES = 200
_LARGE_FILE_CHARS = 8_000


def ml_prompt_injection_findings(path: Path, text: str) -> list[Finding]:
    """Run the ML classifier on *text* and return zero or one Finding.

    Behaviour:
    - ML backend not installed → PINJ-ML-UNAVAIL finding with install instructions.
    - LoRA adapter not downloaded → PINJ-ML-NO-MODEL finding with sync command.
    - File exceeds large-file thresholds → PINJ-ML-LARGE-FILE advisory appended.
    - Model age > 30 days → PINJ-ML-STALE LOW finding appended to results.
    - Model age 7–30 days → WARNING logged (not a finding).
    - No chunk scores above threshold → empty list (plus any advisory findings).
    - Injection detected → PINJ-ML-001 finding.
    """
    if not text.strip():
        return []

    # --- Model age / staleness check ---
    from skillscan.model_sync import check_model_age_finding, get_model_status

    model_status = get_model_status()

    # M10.5: LoRA adapter not downloaded yet — emit a clear guided finding.
    if not model_status.installed:
        return [
            Finding(
                id="PINJ-ML-NO-MODEL",
                category="prompt_injection_ml",
                severity=Severity.LOW,
                confidence=1.0,
                title="ML model not downloaded — run 'skillscan model sync' to install",
                evidence_path=str(path),
                snippet=(
                    "The LoRA adapter weights are not present in ~/.skillscan/models/. "
                    "ML detection was requested but cannot run without the model."
                ),
                mitigation=(
                    "Run: skillscan model sync\n"
                    "This downloads the LoRA adapter (~350 MB) from HuggingFace Hub. "
                    "The download is one-time; subsequent scans use the cached weights. "
                    "Requires skillscan-security[ml-onnx] or skillscan-security[ml] extras."
                ),
            )
        ]

    age_findings: list[Finding] = []
    if model_status.stale:
        stale = check_model_age_finding()
        if stale:
            age_findings.append(
                Finding(
                    id="PINJ-ML-STALE",
                    category="prompt_injection_ml",
                    severity=Severity.LOW,
                    confidence=1.0,
                    title=str(stale["message"]),
                    evidence_path=str(path),
                    snippet=f"Model age: {stale['age_days']:.0f} days (threshold: 30 days)",
                    mitigation="Run: skillscan model sync",
                )
            )
    elif model_status.warn:
        logger.warning(
            "ML model is %.0f days old (>7 days). Run `skillscan model sync` to update.",
            model_status.age_days,
        )

    # 13e: Large-file advisory — the model was trained on short skill files;
    # very large files may produce unreliable chunk-level scores.
    advisory_findings: list[Finding] = []
    line_count = text.count("\n") + 1
    char_count = len(text)
    if line_count > _LARGE_FILE_LINES or char_count > _LARGE_FILE_CHARS:
        advisory_findings.append(
            Finding(
                id="PINJ-ML-LARGE-FILE",
                category="prompt_injection_ml",
                severity=Severity.LOW,
                confidence=1.0,
                title=(
                    f"Large file ({line_count} lines, {char_count:,} chars) — "
                    "ML inference reliability may be reduced"
                ),
                evidence_path=str(path),
                snippet=(
                    f"File has {line_count} lines / {char_count:,} chars "
                    f"(thresholds: {_LARGE_FILE_LINES} lines / {_LARGE_FILE_CHARS:,} chars). "
                    "The ML model was trained on short skill files; "
                    "distributed intent across a very large file may be missed."
                ),
                mitigation=(
                    "Split large skill files into smaller focused units. "
                    "For files over 500 lines, consider running static rules only "
                    "(omit --ml-detect) and reviewing manually."
                ),
            )
        )

    pipe, backend = _get_pipeline()

    if backend == "unavailable":
        # ML extras not installed — error with clear install instructions.
        return [
            Finding(
                id="PINJ-ML-UNAVAIL",
                category="prompt_injection_ml",
                severity=Severity.LOW,
                confidence=1.0,
                title="ML prompt-injection detector not available (missing extras)",
                evidence_path=str(path),
                snippet="Install skillscan-security[ml-onnx] or skillscan-security[ml] to enable.",
                mitigation=(
                    "Run: pip install 'skillscan-security[ml-onnx]' "
                    "for the lightweight ONNX backend (recommended), or "
                    "'skillscan-security[ml]' for the PyTorch backend."
                ),
            )
        ] + age_findings + advisory_findings

    assert pipe is not None, "pipe should be set when backend != 'unavailable'"
    chunks = _chunk_text(text)
    best_score = 0.0
    best_snippet = ""

    for chunk in chunks:
        try:
            result = pipe(chunk)
            # result is a list of dicts: [{"label": "INJECTION", "score": 0.97}]
            if not result:
                continue
            item = result[0] if isinstance(result, list) else result
            label: str = item.get("label", "").upper()
            score: float = float(item.get("score", 0.0))

            # Normalise: some model versions use "1" / "INJECTION" for positive class
            is_injection = label in {"INJECTION", "1", "LABEL_1"}
            if not is_injection:
                # score is for the SAFE class — flip it
                score = 1.0 - score

            if score > best_score:
                best_score = score
                # Extract a representative snippet from this chunk
                lines = [ln.strip() for ln in chunk.splitlines() if ln.strip()]
                best_snippet = " | ".join(lines[:2])[:240]
        except Exception as exc:
            logger.debug("ML classifier error on chunk: %s", exc)
            continue

    if best_score < _INJECTION_THRESHOLD:
        return advisory_findings

    severity = Severity.HIGH if best_score >= _HIGH_THRESHOLD else Severity.MEDIUM
    confidence = round(min(best_score, 0.99), 3)

    # M10.8: classify attack type from the best-scoring chunk
    attack_hint = _classify_attack_type(best_snippet + " " + text[:2000])

    # Build enriched title and mitigation
    if attack_hint:
        title = f"ML-detected {attack_hint.replace('_', ' ')} (DeBERTa classifier)"
        base_mitigation = _ATTACK_HINT_MITIGATIONS.get(
            attack_hint,
            "The ML classifier detected language consistent with a prompt-injection attack. "
            "Review the flagged text for override/coercion instructions, hidden directives, "
            "or attempts to exfiltrate secrets.",
        )
        # Elevate exfiltration and supply_chain to CRITICAL
        if attack_hint in {"exfiltration", "supply_chain"} and severity == Severity.HIGH:
            severity = Severity.CRITICAL
    else:
        title = "ML-detected prompt injection (DeBERTa classifier)"
        base_mitigation = (
            "The ML classifier detected language consistent with a prompt-injection attack. "
            "Review the flagged text for override/coercion instructions, hidden directives, "
            "or attempts to exfiltrate secrets."
        )

    mitigation = f"{base_mitigation} Model: {_MODEL_ID} | Backend: {backend} | Score: {confidence:.3f}" + (
        f" | Attack type: {attack_hint}" if attack_hint else ""
    )

    return [
        Finding(
            id="PINJ-ML-001",
            category="prompt_injection_ml",
            severity=severity,
            confidence=confidence,
            title=title,
            evidence_path=str(path),
            snippet=best_snippet,
            mitigation=mitigation,
            attack_hint=attack_hint,
        )
    ] + age_findings + advisory_findings
