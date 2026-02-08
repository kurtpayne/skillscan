# Architecture

## High-level flow

1. Input path resolution and archive-safe extraction.
2. Text file iteration with binary/cache filtering.
3. Instruction hardening (Unicode normalization, zero-width stripping, bounded base64 decoding).
4. Pattern and action-chain analysis for malware and instruction abuse.
5. IOC extraction and local intel correlation.
6. Dependency vulnerability and unpinned version checks.
7. Capability inference.
8. Policy scoring and verdicting.
9. Report generation and output rendering.

## Core modules

- `src/skillscan/cli.py`: command surface
- `src/skillscan/analysis.py`: scan pipeline
- `src/skillscan/policies.py`: built-in/custom policy loading
- `src/skillscan/intel.py`: local intel source management
- `src/skillscan/ecosystems.py`: ecosystem hint detection
- `src/skillscan/models.py`: report/policy data models
- `src/skillscan/render.py`: formatted terminal rendering

## Data

- Built-in policy YAML: `src/skillscan/data/policies/`
- Built-in intel JSON: `src/skillscan/data/intel/`
- Runtime intel config: `~/.skillscan/intel_sources.json`
- Runtime copied intel files: `~/.skillscan/intel/`

## Determinism notes

Given identical input, policy, and intel source set, scan outputs are deterministic.
