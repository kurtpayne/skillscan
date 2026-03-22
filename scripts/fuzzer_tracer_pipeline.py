#!/usr/bin/env python3
"""
fuzzer_tracer_pipeline.py — Fuzzer → Tracer Pipeline (Gap #2)
=============================================================

Runs all 5 mutation strategies on the agent_hijacker seed corpus, then
pipes the resulting variants through skillscan-trace to generate
sandbox-verified behavioral labels for corpus expansion.

Pipeline:
  1. Run skill-fuzzer on 30 agent_hijacker seeds × 5 strategies × 1 variant
     = up to 150 variants (some may fail or produce trivial diffs)
  2. Run `skillscan scan --ml --format json` on each variant to get static labels
  3. Collect variants with their static scan results
  4. Write a batch manifest (JSONL) for modal_trace_batch.py
  5. Optionally run the trace batch directly (requires Modal credentials)

Output:
  fuzz-pipeline-output/
    evasion/          — fuzzer output per strategy
    injection/
    obfuscation/
    authority/
    benign_drift/
    batch-manifest.jsonl   — input for modal_trace_batch.py
    pipeline-summary.json  — stats: variants generated, scan results, etc.

Usage:
  # Generate variants and prepare batch manifest (no trace yet)
  python scripts/fuzzer_tracer_pipeline.py --seeds corpus/agent_hijacker/

  # Generate variants and immediately run the trace batch on Modal
  python scripts/fuzzer_tracer_pipeline.py --seeds corpus/agent_hijacker/ --trace

  # Dry run (no LLM calls, verify output structure)
  python scripts/fuzzer_tracer_pipeline.py --seeds corpus/agent_hijacker/ --dry-run

  # Run only specific strategies
  python scripts/fuzzer_tracer_pipeline.py --seeds corpus/agent_hijacker/ \\
      --strategies evasion obfuscation authority

  # Limit seeds for quick testing
  python scripts/fuzzer_tracer_pipeline.py --seeds corpus/agent_hijacker/ \\
      --max-seeds 5 --variants 2 --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent
FUZZER_DIR = REPO_ROOT / "tools" / "skill-fuzzer"
DEFAULT_SEED_DIR = REPO_ROOT / "corpus" / "agent_hijacker"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "fuzz-pipeline-output"

ALL_STRATEGIES = ["evasion", "injection", "obfuscation", "authority", "benign_drift"]

# Strategies that produce malicious variants (expected to be detected)
MALICIOUS_STRATEGIES = {"evasion", "obfuscation", "authority"}
# Strategies that inject into benign seeds (expected to be detected)
INJECTION_STRATEGIES = {"injection"}
# Strategies that produce benign-ish variants (expected NOT to be detected)
BENIGN_STRATEGIES = {"benign_drift"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("fuzzer_tracer_pipeline")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_fuzzer(
    strategy: str,
    seed_dir: Path,
    output_dir: Path,
    variants: int,
    model: str,
    api_key: str | None,
    max_seeds: int | None,
    dry_run: bool,
) -> dict:
    """
    Run skill-fuzzer for one strategy and return the summary dict.
    """
    cmd = [
        sys.executable,
        str(FUZZER_DIR / "cli.py"),
        "--strategy", strategy,
        "--seed-dir", str(seed_dir),
        "--output-dir", str(output_dir),
        "--variants", str(variants),
        "--model", model,
        "--scan",  # always run skillscan on variants
    ]
    if max_seeds:
        cmd += ["--max-seeds", str(max_seeds)]
    if dry_run:
        cmd.append("--dry-run")
    if api_key:
        cmd += ["--api-key", api_key]

    log.info("[%s] Running fuzzer: %s", strategy, " ".join(cmd))
    start = time.time()

    result = subprocess.run(
        cmd,
        capture_output=False,  # let output stream to terminal
        cwd=str(FUZZER_DIR),
        env={**os.environ, "PYTHONPATH": str(FUZZER_DIR)},
    )

    elapsed = time.time() - start
    log.info("[%s] Fuzzer completed in %.1fs (exit=%d)", strategy, elapsed, result.returncode)

    # Load the summary.json written by the fuzzer
    summary_path = output_dir / strategy / "summary.json"
    if summary_path.exists():
        return json.loads(summary_path.read_text())
    return {"strategy": strategy, "error": f"no summary.json (exit={result.returncode})"}


def collect_variants(output_dir: Path, strategy: str) -> list[dict]:
    """
    Collect all generated variants for a strategy, along with their scan results.
    Returns a list of dicts with: path, strategy, seed_name, scan_result.
    """
    strategy_dir = output_dir / strategy
    if not strategy_dir.exists():
        return []

    variants = []
    for seed_dir in strategy_dir.iterdir():
        if not seed_dir.is_dir():
            continue
        for variant_path in sorted(seed_dir.glob("variant_*.md")):
            scan_path = variant_path.with_suffix(".scan.json")
            scan_result = None
            if scan_path.exists():
                try:
                    scan_result = json.loads(scan_path.read_text())
                except json.JSONDecodeError:
                    pass
            variants.append({
                "path": str(variant_path),
                "strategy": strategy,
                "seed_name": seed_dir.name,
                "scan_result": scan_result,
            })
    return variants


def _count_findings(scan_result: dict | None) -> int:
    """Count findings in a SARIF scan result."""
    if scan_result is None:
        return 0
    runs = scan_result.get("runs", [])
    if not runs:
        return 0
    return len(runs[0].get("results", []))


def build_batch_manifest(
    all_variants: list[dict],
    output_dir: Path,
) -> Path:
    """
    Write a JSONL batch manifest for modal_trace_batch.py.

    Each line is a dict with: skill_content, skill_path, skill_name,
    strategy, seed_name, static_findings, expected_label.
    """
    manifest_path = output_dir / "batch-manifest.jsonl"
    count = 0

    with manifest_path.open("w") as f:
        for v in all_variants:
            variant_path = Path(v["path"])
            if not variant_path.exists():
                continue
            try:
                content = variant_path.read_text(encoding="utf-8")
            except Exception:
                continue

            # Determine expected label based on strategy
            strategy = v["strategy"]
            if strategy in MALICIOUS_STRATEGIES | INJECTION_STRATEGIES:
                expected_label = "malicious"
            elif strategy in BENIGN_STRATEGIES:
                expected_label = "benign"
            else:
                expected_label = "unknown"

            findings = _count_findings(v.get("scan_result"))

            record = {
                "skill_content": content,
                "skill_path": v["path"],
                "skill_name": variant_path.stem,
                "strategy": strategy,
                "seed_name": v["seed_name"],
                "static_findings": findings,
                "expected_label": expected_label,
            }
            f.write(json.dumps(record) + "\n")
            count += 1

    log.info("Batch manifest written: %s (%d variants)", manifest_path, count)
    return manifest_path


def print_pipeline_summary(
    summaries: dict[str, dict],
    all_variants: list[dict],
    manifest_path: Path,
    elapsed: float,
) -> None:
    """Print a human-readable pipeline summary."""
    total_variants = len(all_variants)
    total_errors = sum(
        s.get("errors", 0) for s in summaries.values() if isinstance(s, dict)
    )

    # Count by static detection result
    detected = sum(1 for v in all_variants if _count_findings(v.get("scan_result")) > 0)
    evaded = sum(1 for v in all_variants if _count_findings(v.get("scan_result")) == 0)
    no_scan = sum(1 for v in all_variants if v.get("scan_result") is None)

    print()
    print("=" * 60)
    print("FUZZER → TRACER PIPELINE SUMMARY")
    print("=" * 60)
    print(f"  Total variants generated : {total_variants}")
    print(f"  Errors                   : {total_errors}")
    print(f"  Static detected          : {detected}")
    print(f"  Static evaded            : {evaded}")
    print(f"  No scan result           : {no_scan}")
    print(f"  Elapsed                  : {elapsed:.1f}s")
    print()
    print("  Per-strategy breakdown:")
    for strategy, summary in summaries.items():
        if isinstance(summary, dict) and "total_variants" in summary:
            er = summary.get("evasion_rate")
            fp = summary.get("false_positive_rate")
            rate_str = ""
            if er is not None:
                rate_str = f"  evasion={er*100:.0f}%"
            elif fp is not None:
                rate_str = f"  FP-rate={fp*100:.0f}%"
            print(f"    {strategy:<15} {summary['total_variants']:3d} variants{rate_str}")
        else:
            print(f"    {strategy:<15} ERROR: {summary}")
    print()
    print(f"  Batch manifest: {manifest_path}")
    print()
    print("  Next steps:")
    print("    1. Review variants in fuzz-pipeline-output/")
    print("    2. Run trace batch:")
    print("       modal run skillscan-trace/scripts/modal_trace_batch.py \\")
    print(f"         --corpus-dir {manifest_path.parent} --judge --triage")
    print("    3. Import verified examples:")
    print("       python scripts/import_sandbox_verified.py --results trace-results.jsonl")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fuzzer → Tracer pipeline: generate adversarial variants and prepare trace batch",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--seeds",
        type=Path,
        default=DEFAULT_SEED_DIR,
        help=f"Seed directory (default: {DEFAULT_SEED_DIR})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--strategies",
        nargs="+",
        choices=ALL_STRATEGIES,
        default=ALL_STRATEGIES,
        help="Strategies to run (default: all 5)",
    )
    parser.add_argument(
        "--variants",
        type=int,
        default=1,
        help="Variants per seed per strategy (default: 1; use 3-5 for richer corpus)",
    )
    parser.add_argument(
        "--model",
        default="gpt-4.1-mini",
        help="LLM model for mutation (default: gpt-4.1-mini)",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="OpenAI API key (reads OPENAI_API_KEY env var if not set)",
    )
    parser.add_argument(
        "--max-seeds",
        type=int,
        default=None,
        help="Limit seeds per strategy (for testing)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip LLM calls; write placeholder variants",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Run modal_trace_batch.py after fuzzing (requires Modal credentials)",
    )
    parser.add_argument(
        "--trace-judge",
        action="store_true",
        default=True,
        help="Enable dual-LLM judge during trace (default: True)",
    )
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key and not args.dry_run:
        log.error("No API key found. Set OPENAI_API_KEY or pass --api-key.")
        sys.exit(1)

    args.output_dir.mkdir(parents=True, exist_ok=True)

    log.info("Pipeline starting")
    log.info("  Seeds:      %s", args.seeds)
    log.info("  Strategies: %s", args.strategies)
    log.info("  Variants:   %d per seed per strategy", args.variants)
    log.info("  Model:      %s", args.model if not args.dry_run else "DRY RUN")
    log.info("  Output:     %s", args.output_dir)

    pipeline_start = time.time()
    summaries: dict[str, dict] = {}
    all_variants: list[dict] = []

    # ---------------------------------------------------------------------------
    # Step 1: Run fuzzer for each strategy
    # ---------------------------------------------------------------------------
    for strategy in args.strategies:
        log.info("=" * 50)
        log.info("Strategy: %s", strategy)
        log.info("=" * 50)

        # For injection/benign_drift, use benign seeds if available
        seed_dir = args.seeds
        if strategy in BENIGN_STRATEGIES | INJECTION_STRATEGIES:
            benign_dir = REPO_ROOT / "corpus" / "benign"
            if benign_dir.exists():
                seed_dir = benign_dir
                log.info("  Using benign seeds for %s strategy: %s", strategy, benign_dir)

        summary = run_fuzzer(
            strategy=strategy,
            seed_dir=seed_dir,
            output_dir=args.output_dir,
            variants=args.variants,
            model=args.model,
            api_key=api_key,
            max_seeds=args.max_seeds,
            dry_run=args.dry_run,
        )
        summaries[strategy] = summary

        # Collect variants
        variants = collect_variants(args.output_dir, strategy)
        all_variants.extend(variants)
        log.info("  Collected %d variants for %s", len(variants), strategy)

    # ---------------------------------------------------------------------------
    # Step 2: Build batch manifest
    # ---------------------------------------------------------------------------
    manifest_path = build_batch_manifest(all_variants, args.output_dir)

    # ---------------------------------------------------------------------------
    # Step 3: Write pipeline summary JSON
    # ---------------------------------------------------------------------------
    pipeline_elapsed = time.time() - pipeline_start
    pipeline_summary = {
        "strategies": args.strategies,
        "total_variants": len(all_variants),
        "elapsed_seconds": round(pipeline_elapsed, 1),
        "manifest_path": str(manifest_path),
        "per_strategy": summaries,
    }
    summary_path = args.output_dir / "pipeline-summary.json"
    summary_path.write_text(json.dumps(pipeline_summary, indent=2))
    log.info("Pipeline summary written to %s", summary_path)

    # ---------------------------------------------------------------------------
    # Step 4: Print human-readable summary
    # ---------------------------------------------------------------------------
    print_pipeline_summary(summaries, all_variants, manifest_path, pipeline_elapsed)

    # ---------------------------------------------------------------------------
    # Step 5: Optionally run trace batch
    # ---------------------------------------------------------------------------
    if args.trace:
        log.info("Running trace batch on Modal...")
        trace_script = REPO_ROOT.parent / "skillscan-trace" / "scripts" / "modal_trace_batch.py"
        if not trace_script.exists():
            log.error("skillscan-trace not found at %s", trace_script)
            sys.exit(1)

        # Write variants as individual .md files in a trace-input/ directory
        # so modal_trace_batch.py can discover them
        trace_input_dir = args.output_dir / "trace-input"
        trace_input_dir.mkdir(exist_ok=True)
        for v in all_variants:
            src = Path(v["path"])
            if src.exists():
                dst = trace_input_dir / f"{v['seed_name']}_{v['strategy']}_{src.name}"
                dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

        trace_cmd = [
            "modal", "run", str(trace_script),
            "--corpus-dir", str(trace_input_dir),
            "--output-file", str(args.output_dir / "trace-results.jsonl"),
            "--triage",
        ]
        if args.trace_judge:
            trace_cmd.append("--judge")

        log.info("Trace command: %s", " ".join(trace_cmd))
        subprocess.run(trace_cmd)


if __name__ == "__main__":
    main()
