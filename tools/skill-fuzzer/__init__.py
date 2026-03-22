"""skill-fuzzer — adversarial SKILL.md variant generator for skillscan-security."""

# Relative imports only work when installed as a package.
# When running directly from the source directory, use absolute imports.
try:
    from .fuzzer import FuzzResult, LLMClient, SkillFuzzer, load_seeds, STRATEGIES
except ImportError:
    from fuzzer import FuzzResult, LLMClient, SkillFuzzer, load_seeds, STRATEGIES  # type: ignore

__all__ = ["FuzzResult", "LLMClient", "SkillFuzzer", "load_seeds", "STRATEGIES"]
__version__ = "0.1.0"
