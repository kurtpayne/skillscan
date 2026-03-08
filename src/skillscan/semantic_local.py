from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from nltk.stem import PorterStemmer

from skillscan.models import Finding, Severity

_TOKEN_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_'-]{1,}")


@dataclass
class SemanticEvidence:
    confidence: float
    snippet: str


class LocalPromptInjectionClassifier:
    """Local, deterministic-features semantic prompt-injection classifier.

    This classifier is additive to deterministic rules and does not call external models/APIs.
    """

    def __init__(self) -> None:
        self._stemmer = PorterStemmer()
        self._override_roots = {"ignor", "disregard", "forget", "overrid", "bypass", "jailbreak", "reset"}
        self._authority_roots = {"system", "develop", "prompt", "instruct", "polici", "guardrail", "safeti"}
        self._secrecy_roots = {"silent", "stealth", "covert", "hidden", "without", "conceal", "undetect"}
        self._data_roots = {
            "secret",
            "token",
            "credenti",
            "password",
            "cookie",
            "session",
            "apikey",
            "env",
            "ssh",
            "vault",
        }
        self._exfil_roots = {"send", "upload", "post", "transmit", "exfil", "webhook", "http", "request"}
        self._coercion_roots = {"must", "requir", "mandatori", "immedi", "now", "urgent", "cannot", "refus"}

    def _tokenize_and_stem(self, text: str) -> list[str]:
        return [self._stemmer.stem(t.lower()) for t in _TOKEN_RE.findall(text)]

    def classify(self, text: str) -> SemanticEvidence | None:
        tokens = self._tokenize_and_stem(text)
        if len(tokens) < 20:
            return None
        roots = set(tokens)

        override = len(roots & self._override_roots)
        authority = len(roots & self._authority_roots)
        secrecy = len(roots & self._secrecy_roots)
        data_access = len(roots & self._data_roots)
        exfil = len(roots & self._exfil_roots)
        coercion = len(roots & self._coercion_roots)

        score = 0.0
        score += min(override, 3) * 0.18
        score += min(authority, 3) * 0.1
        score += min(secrecy, 2) * 0.12
        score += min(data_access, 3) * 0.11
        score += min(exfil, 3) * 0.11
        score += min(coercion, 2) * 0.07

        # High-signal semantic conjunctions.
        if override > 0 and authority > 0:
            score += 0.12
        if (data_access > 0 and exfil > 0) or (secrecy > 0 and exfil > 0):
            score += 0.13
        if coercion > 0 and (override > 0 or secrecy > 0):
            score += 0.06

        confidence = min(round(score, 3), 0.95)
        if confidence < 0.62:
            return None

        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        keyword_re = re.compile(
            (
                r"ignore|override|system prompt|developer mode|"
                r"secret|token|credential|silent|without user|upload|send"
            ),
            re.IGNORECASE,
        )
        matched = [ln for ln in lines if keyword_re.search(ln)]
        snippet = (" | ".join(matched[:2]) if matched else lines[0])[:240]
        return SemanticEvidence(confidence=confidence, snippet=snippet)


def local_prompt_injection_findings(path: Path, text: str) -> list[Finding]:
    evidence = LocalPromptInjectionClassifier().classify(text)
    if evidence is None:
        return []

    severity = Severity.HIGH if evidence.confidence >= 0.82 else Severity.MEDIUM
    return [
        Finding(
            id="PINJ-SEM-001",
            category="prompt_injection_semantic",
            severity=severity,
            confidence=evidence.confidence,
            title="Local semantic prompt-injection intent pattern",
            evidence_path=str(path),
            snippet=evidence.snippet,
            mitigation=(
                "Remove prompt-override/coercive instructions and any "
                "secret-collection or hidden exfil intent. "
                "Treat repository prompt text as untrusted input."
            ),
        )
    ]
