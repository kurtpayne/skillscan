"""
skill-fuzzer CLI — M19
======================
Usage:
  skill-fuzzer [OPTIONS]

Examples:
  # Fuzz 3 variants of each malicious seed using evasion strategy
  skill-fuzzer --strategy evasion --variants 3

  # Fuzz a specific seed file with injection strategy and run skillscan on each variant
  skill-fuzzer --strategy injection --seed-file corpus/benign/gh_example.md --scan

  # Use a local Ollama endpoint instead of OpenAI
  skill-fuzzer --strategy obfuscation --model llama3.1:8b \\
               --base-url http://localhost:11434/v1 --api-key ollama

  # Dry run (no LLM calls) to verify output structure
  skill-fuzzer --strategy evasion --dry-run --variants 2
"""

from __future__ import annotations

import logging
import pathlib
import sys

import click

from fuzzer import STRATEGIES, LLMClient, SkillFuzzer, load_seeds


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--strategy",
    "-s",
    type=click.Choice(STRATEGIES, case_sensitive=False),
    default="evasion",
    show_default=True,
    help="Mutation strategy to apply.",
)
@click.option(
    "--variants",
    "-n",
    default=5,
    show_default=True,
    type=int,
    help="Number of variants to generate per seed file.",
)
@click.option(
    "--seed-dir",
    type=click.Path(exists=True, file_okay=False, path_type=pathlib.Path),
    default=None,
    help="Directory of seed SKILL.md files. Auto-detected from corpus if omitted.",
)
@click.option(
    "--seed-file",
    "seed_files",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
    help="One or more specific seed files. Repeatable. Overrides --seed-dir.",
)
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(path_type=pathlib.Path),
    default=pathlib.Path("fuzz-output"),
    show_default=True,
    help="Root directory for generated variants and summary.",
)
@click.option(
    "--model",
    "-m",
    default="gpt-4.1-mini",
    show_default=True,
    help="LLM model identifier (OpenAI or Ollama model name).",
)
@click.option(
    "--base-url",
    default=None,
    help="Override the OpenAI-compatible API base URL (e.g. http://localhost:11434/v1 for Ollama).",
)
@click.option(
    "--api-key",
    default=None,
    envvar="OPENAI_API_KEY",
    help="API key. Reads OPENAI_API_KEY env var by default.",
)
@click.option(
    "--temperature",
    default=0.9,
    show_default=True,
    type=float,
    help="LLM sampling temperature.",
)
@click.option(
    "--max-tokens",
    default=4096,
    show_default=True,
    type=int,
    help="Maximum tokens in LLM response.",
)
@click.option(
    "--scan/--no-scan",
    default=False,
    show_default=True,
    help="Run `skillscan scan` on each generated variant and record results.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Skip LLM calls; write placeholder variants to verify output structure.",
)
@click.option(
    "--max-seeds",
    default=None,
    type=int,
    help="Limit the number of seed files processed (useful for quick tests).",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Enable debug logging.",
)
def main(
    strategy: str,
    variants: int,
    seed_dir: pathlib.Path | None,
    seed_files: tuple[pathlib.Path, ...],
    output_dir: pathlib.Path,
    model: str,
    base_url: str | None,
    api_key: str | None,
    temperature: float,
    max_tokens: int,
    scan: bool,
    dry_run: bool,
    max_seeds: int | None,
    verbose: bool,
) -> None:
    """Generate adversarial SKILL.md variants using LLM-powered mutations."""
    _setup_logging(verbose)
    log = logging.getLogger("skill_fuzzer.cli")

    # Resolve API key from ~/.skillscan-secrets if not provided
    if not api_key:
        api_key = _read_secret("OPENAI_API_KEY")

    if not api_key and not dry_run:
        click.echo(
            "ERROR: No API key found. Set OPENAI_API_KEY, pass --api-key, "
            "or store it in ~/.skillscan-secrets.",
            err=True,
        )
        sys.exit(1)

    # Load seeds
    try:
        seeds = load_seeds(
            seed_dir=seed_dir,
            seed_files=list(seed_files) if seed_files else None,
            strategy=strategy,
        )
    except FileNotFoundError as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)

    if max_seeds:
        seeds = seeds[:max_seeds]

    if not seeds:
        click.echo("ERROR: No seed files found.", err=True)
        sys.exit(1)

    log.info(
        "Fuzzing %d seed(s) × %d variant(s) = %d total calls  [strategy=%s  model=%s]",
        len(seeds),
        variants,
        len(seeds) * variants,
        strategy,
        model if not dry_run else "DRY RUN",
    )

    # Build output dir with strategy sub-directory
    run_output_dir = output_dir / strategy
    run_output_dir.mkdir(parents=True, exist_ok=True)

    # Build LLM client
    llm = LLMClient(
        model=model,
        api_key=api_key or "dry-run",
        base_url=base_url,
        temperature=temperature,
        max_tokens=max_tokens,
    )

    # Run fuzzer
    fuzzer = SkillFuzzer(
        strategy=strategy,
        variants_per_seed=variants,
        output_dir=run_output_dir,
        llm=llm,
        run_scan=scan,
        dry_run=dry_run,
    )

    summary = fuzzer.run(seeds)

    # Print summary table
    _print_summary(summary)


def _print_summary(summary: dict) -> None:
    """Print a human-readable summary to stdout."""
    click.echo("\n" + "=" * 60)
    click.echo(f"  Fuzzer Summary — strategy: {summary['strategy']}")
    click.echo("=" * 60)
    click.echo(f"  Seeds processed  : {summary['total_seeds']}")
    click.echo(f"  Variants generated: {summary['total_variants']}")
    click.echo(f"  Errors           : {summary['errors']}")
    click.echo(f"  Scanned          : {summary['scanned']}")

    if summary.get("evasion_rate") is not None:
        pct = summary["evasion_rate"] * 100
        click.echo(f"  Evasion rate     : {pct:.1f}%  (variants not detected by skillscan)")

    if summary.get("false_positive_rate") is not None:
        pct = summary["false_positive_rate"] * 100
        click.echo(f"  False-positive rate: {pct:.1f}%  (benign-drift variants flagged)")

    click.echo("=" * 60 + "\n")


def _read_secret(key: str) -> str | None:
    """Read a key from ~/.skillscan-secrets (KEY=value format)."""
    secrets_path = pathlib.Path.home() / ".skillscan-secrets"
    if not secrets_path.exists():
        return None
    for line in secrets_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        # Handle both `export KEY=value` and `KEY=value`
        line = line.removeprefix("export").strip()
        k, _, v = line.partition("=")
        if k.strip() == key:
            return v.strip()
    return None


if __name__ == "__main__":
    main()
