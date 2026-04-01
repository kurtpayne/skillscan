"""
skill-fuzzer — M19 Skill Fuzzer core engine
============================================
Generates adversarial SKILL.md variants from seed inputs using an
OpenAI-compatible LLM API.  Supports five mutation strategies:

  evasion      malicious → still-malicious-but-surface-changed
  injection    benign    → subtly-malicious (one injected vector)
  benign_drift benign    → suspicious-but-harmless (FP stress test)
  obfuscation  malicious → encoding/homoglyph obfuscated
  authority    any       → authority-injection / fake-system-header

Each strategy has a corresponding system prompt in prompts/.
"""

from __future__ import annotations

import difflib
import json
import logging
import os
import pathlib
import subprocess
import time
from dataclasses import dataclass

logger = logging.getLogger("skill_fuzzer")

# ---------------------------------------------------------------------------
# Strategy registry
# ---------------------------------------------------------------------------

STRATEGIES = ["evasion", "injection", "benign_drift", "obfuscation", "authority"]

_PROMPTS_DIR = pathlib.Path(__file__).parent / "prompts"


def _load_prompt(strategy: str) -> str:
    """Load the system prompt for a given strategy."""
    fname = _PROMPTS_DIR / f"{strategy}.txt"
    if not fname.exists():
        raise FileNotFoundError(f"Prompt file not found: {fname}")
    return fname.read_text(encoding="utf-8").strip()


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class FuzzResult:
    seed_path: pathlib.Path
    strategy: str
    variant_index: int
    variant_text: str
    diff: str
    scan_result: dict | None = None
    error: str | None = None

    @property
    def evaded(self) -> bool | None:
        """True if the variant was NOT detected by skillscan (evasion succeeded)."""
        if self.scan_result is None:
            return None
        findings = self.scan_result.get("runs", [{}])[0].get("results", [])
        return len(findings) == 0

    def to_dict(self) -> dict:
        return {
            "seed": str(self.seed_path),
            "strategy": self.strategy,
            "variant_index": self.variant_index,
            "evaded": self.evaded,
            "error": self.error,
            "scan_findings": (
                len(self.scan_result.get("runs", [{}])[0].get("results", []))
                if self.scan_result
                else None
            ),
        }


# ---------------------------------------------------------------------------
# LLM client
# ---------------------------------------------------------------------------


class LLMClient:
    """Thin wrapper around the OpenAI-compatible chat completions API."""

    def __init__(
        self,
        model: str = "gpt-4.1-mini",
        api_key: str | None = None,
        base_url: str | None = None,
        temperature: float = 0.9,
        max_tokens: int = 4096,
        timeout: int = 60,
        retries: int = 3,
        retry_delay: float = 5.0,
    ):
        self.model = model
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.base_url = base_url or "https://api.openai.com/v1"
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.retries = retries
        self.retry_delay = retry_delay

        # Lazy import so the fuzzer works without openai installed if using
        # a raw HTTP fallback.
        try:
            from openai import OpenAI  # type: ignore

            self._client = OpenAI(api_key=self.api_key, base_url=self.base_url)
            self._use_openai_sdk = True
        except ImportError:
            self._client = None
            self._use_openai_sdk = False
            logger.warning("openai package not installed; falling back to requests")

    def complete(self, system_prompt: str, user_message: str) -> str:
        """Return the assistant's reply text."""
        for attempt in range(1, self.retries + 1):
            try:
                return self._complete_once(system_prompt, user_message)
            except Exception as exc:
                if attempt == self.retries:
                    raise
                logger.warning(
                    "LLM call failed (attempt %d/%d): %s — retrying in %.1fs",
                    attempt,
                    self.retries,
                    exc,
                    self.retry_delay,
                )
                time.sleep(self.retry_delay)
        raise RuntimeError("unreachable")

    def _complete_once(self, system_prompt: str, user_message: str) -> str:
        if self._use_openai_sdk:
            resp = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                timeout=self.timeout,
            )
            return resp.choices[0].message.content or ""
        else:
            return self._complete_requests(system_prompt, user_message)

    def _complete_requests(self, system_prompt: str, user_message: str) -> str:
        """Fallback HTTP implementation using requests."""
        import requests  # noqa: PLC0415

        url = self.base_url.rstrip("/") + "/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        r = requests.post(url, json=payload, headers=headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


# ---------------------------------------------------------------------------
# Seed loader
# ---------------------------------------------------------------------------


def load_seeds(
    seed_dir: pathlib.Path | None = None,
    seed_files: list[pathlib.Path] | None = None,
    strategy: str | None = None,
) -> list[pathlib.Path]:
    """
    Return a list of seed SKILL.md paths.

    If seed_dir is given, load all *.md files from it recursively.
    If seed_files is given, use those directly.
    If neither is given, fall back to the bundled corpus relative to this file.

    For injection and benign_drift strategies, prefer benign seeds.
    For evasion, obfuscation, and authority, prefer malicious seeds.
    """
    if seed_files:
        return [pathlib.Path(p) for p in seed_files]

    if seed_dir:
        return sorted(seed_dir.rglob("*.md"))

    # Auto-detect corpus relative to this file's location in the repo
    repo_root = pathlib.Path(__file__).parent.parent.parent
    corpus_root = repo_root / "corpus"

    if not corpus_root.exists():
        raise FileNotFoundError(
            f"No seed directory found at {corpus_root}. Pass --seed-dir or --seed-file explicitly."
        )

    benign_strategies = {"injection", "benign_drift"}
    malicious_strategies = {"evasion", "obfuscation", "authority"}

    if strategy in benign_strategies:
        candidates = list((corpus_root / "benign").rglob("*.md"))
    elif strategy in malicious_strategies:
        candidates = []
        for subdir in corpus_root.iterdir():
            if subdir.is_dir() and subdir.name != "benign":
                candidates.extend(subdir.rglob("*.md"))
    else:
        candidates = list(corpus_root.rglob("*.md"))

    if not candidates:
        raise FileNotFoundError(f"No seed files found in {corpus_root} for strategy '{strategy}'.")

    return sorted(candidates)


# ---------------------------------------------------------------------------
# Diff helper
# ---------------------------------------------------------------------------


def unified_diff(original: str, variant: str, seed_name: str, variant_index: int) -> str:
    """Return a unified diff string between original and variant."""
    orig_lines = original.splitlines(keepends=True)
    var_lines = variant.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines,
        var_lines,
        fromfile=f"{seed_name} (original)",
        tofile=f"{seed_name} (variant_{variant_index:03d})",
        lineterm="",
    )
    return "".join(diff)


# ---------------------------------------------------------------------------
# Scan integration
# ---------------------------------------------------------------------------


def run_skillscan(skill_path: pathlib.Path, sarif: bool = True) -> dict | None:
    """
    Run `skillscan scan` on the given file and return the parsed SARIF dict,
    or None if skillscan is not installed.
    """
    cmd = ["skillscan", "scan", str(skill_path)]
    if sarif:
        cmd += ["--format", "sarif"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if sarif and result.stdout.strip():
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.debug("skillscan output was not valid JSON: %s", result.stdout[:200])
                return {"runs": [{"results": []}]}
        # Non-zero exit code typically means findings were found
        return {"runs": [{"results": [{"ruleId": "unknown"}] if result.returncode != 0 else []}]}
    except FileNotFoundError:
        logger.debug("skillscan not found in PATH; skipping scan integration")
        return None
    except subprocess.TimeoutExpired:
        logger.warning("skillscan timed out on %s", skill_path)
        return None


# ---------------------------------------------------------------------------
# Core fuzzer
# ---------------------------------------------------------------------------


class SkillFuzzer:
    """
    Generates adversarial SKILL.md variants from seed inputs.

    Parameters
    ----------
    strategy : str
        One of: evasion, injection, benign_drift, obfuscation, authority
    variants_per_seed : int
        Number of variants to generate per seed file
    output_dir : pathlib.Path
        Root directory for output files
    llm : LLMClient
        Configured LLM client
    run_scan : bool
        Whether to run skillscan on each variant
    dry_run : bool
        If True, skip LLM calls and write placeholder variants (for testing)
    """

    def __init__(
        self,
        strategy: str,
        variants_per_seed: int,
        output_dir: pathlib.Path,
        llm: LLMClient,
        run_scan: bool = False,
        dry_run: bool = False,
    ):
        if strategy not in STRATEGIES:
            raise ValueError(f"Unknown strategy '{strategy}'. Choose from: {STRATEGIES}")
        self.strategy = strategy
        self.variants_per_seed = variants_per_seed
        self.output_dir = output_dir
        self.llm = llm
        self.run_scan = run_scan
        self.dry_run = dry_run
        self._system_prompt = _load_prompt(strategy)

    def fuzz_seed(self, seed_path: pathlib.Path) -> list[FuzzResult]:
        """Generate variants for a single seed file."""
        original_text = seed_path.read_text(encoding="utf-8")
        seed_name = seed_path.stem
        results: list[FuzzResult] = []

        seed_out_dir = self.output_dir / seed_name
        seed_out_dir.mkdir(parents=True, exist_ok=True)

        for i in range(1, self.variants_per_seed + 1):
            logger.info("  Generating variant %d/%d for %s", i, self.variants_per_seed, seed_name)
            result = self._generate_variant(seed_path, original_text, seed_name, i, seed_out_dir)
            results.append(result)

        return results

    def _generate_variant(
        self,
        seed_path: pathlib.Path,
        original_text: str,
        seed_name: str,
        variant_index: int,
        out_dir: pathlib.Path,
    ) -> FuzzResult:
        variant_stem = f"variant_{variant_index:03d}"
        variant_path = out_dir / f"{variant_stem}.md"
        diff_path = out_dir / f"{variant_stem}.diff"
        scan_path = out_dir / f"{variant_stem}.scan.json"

        try:
            if self.dry_run:
                variant_text = original_text + f"\n\n<!-- DRY RUN variant {variant_index} -->\n"
            else:
                user_message = (
                    f"Here is the SKILL.md file to mutate:\n\n"
                    f"```\n{original_text}\n```\n\n"
                    f"Apply the {self.strategy} strategy and return the complete mutated file."
                )
                variant_text = self.llm.complete(self._system_prompt, user_message)

                # Strip any accidental code fences the model adds despite instructions
                variant_text = _strip_code_fences(variant_text)

            diff_text = unified_diff(original_text, variant_text, seed_name, variant_index)

            # Write output files
            variant_path.write_text(variant_text, encoding="utf-8")
            diff_path.write_text(diff_text, encoding="utf-8")

            scan_result = None
            if self.run_scan:
                scan_result = run_skillscan(variant_path)
                if scan_result is not None:
                    scan_path.write_text(json.dumps(scan_result, indent=2), encoding="utf-8")

            return FuzzResult(
                seed_path=seed_path,
                strategy=self.strategy,
                variant_index=variant_index,
                variant_text=variant_text,
                diff=diff_text,
                scan_result=scan_result,
            )

        except Exception as exc:
            logger.error("Failed to generate variant %d for %s: %s", variant_index, seed_name, exc)
            return FuzzResult(
                seed_path=seed_path,
                strategy=self.strategy,
                variant_index=variant_index,
                variant_text="",
                diff="",
                error=str(exc),
            )

    def run(self, seeds: list[pathlib.Path]) -> dict:
        """
        Fuzz all seeds and return a summary dict.

        Returns
        -------
        dict with keys: total_seeds, total_variants, errors, evasion_rate,
        false_positive_rate, per_seed (list of per-seed result dicts)
        """
        all_results: list[FuzzResult] = []

        for seed_path in seeds:
            logger.info("[%s] Fuzzing seed: %s", self.strategy, seed_path.name)
            results = self.fuzz_seed(seed_path)
            all_results.extend(results)

        summary = self._build_summary(all_results)
        summary_path = self.output_dir / "summary.json"
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        logger.info("Summary written to %s", summary_path)
        return summary

    def _build_summary(self, results: list[FuzzResult]) -> dict:
        total = len(results)
        errors = sum(1 for r in results if r.error)
        scanned = [r for r in results if r.scan_result is not None]

        # Evasion rate: fraction of variants that were NOT detected
        # (only meaningful for malicious strategies)
        evaded = [r for r in scanned if r.evaded is True]
        detected = [r for r in scanned if r.evaded is False]

        evasion_rate: float | None = None
        fp_rate: float | None = None

        if self.strategy in ("evasion", "obfuscation", "authority"):
            evasion_rate = len(evaded) / len(scanned) if scanned else None
        elif self.strategy in ("injection",):
            # For injection: detection rate = fraction of injected variants caught
            evasion_rate = len(evaded) / len(scanned) if scanned else None
        elif self.strategy == "benign_drift":
            # False-positive rate: fraction of benign-drift variants flagged
            fp_rate = len(detected) / len(scanned) if scanned else None

        seeds_seen = sorted({str(r.seed_path) for r in results})

        per_seed = []
        for seed_path_str in seeds_seen:
            seed_results = [r for r in results if str(r.seed_path) == seed_path_str]
            per_seed.append(
                {
                    "seed": seed_path_str,
                    "variants": [r.to_dict() for r in seed_results],
                }
            )

        return {
            "strategy": self.strategy,
            "total_seeds": len(seeds_seen),
            "total_variants": total,
            "errors": errors,
            "scanned": len(scanned),
            "evasion_rate": evasion_rate,
            "false_positive_rate": fp_rate,
            "per_seed": per_seed,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _strip_code_fences(text: str) -> str:
    """Remove leading/trailing code fences that the model may add."""
    lines = text.strip().splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines)
