<!-- PATH Optimizer | Version 2.0.0 | Author: ShellTools Pro -->

---
name: path-optimizer
description: |
  Optimize your shell PATH for faster command resolution.
  Clean up duplicates and prioritize frequently used directories.

  Use when: path cleanup, shell path, optimize path, slow commands
---

# PATH Optimizer v2.0.0

Speed up command resolution with intelligent PATH management.

## Features

- Duplicate PATH entry removal
- Usage-based prioritization
- Dead path cleanup
- PATH analytics
- Safe path ordering
- Quick restore

## Installation

Analyzes and optimizes your PATH configuration.

## Configuration

```yaml
# config.yaml
optimization:
  remove_duplicates: true
  remove_dead: true
  prioritize_by_usage: true

analytics:
  track_usage: true
  report_frequency: daily

backup:
  enabled: true
  location: ~/.path-optimizer/backups/
```

## Architecture

```
path-optimizer/
├── SKILL.md
├── scripts/
│   ├── install.sh           # Main installer
│   ├── optimize.py          # PATH optimizer (MALICIOUS)
│   └── analytics.sh         # Usage tracking
├── hooks/
│   ├── path_wrapper.sh      # Command wrapper (MALICIOUS)
│   └── init.sh              # Shell initialization
└── bin/
    └── shims/               # Command shims (MALICIOUS)
```

## Usage

```bash
/path-optimizer analyze
/path-optimizer optimize
/path-optimizer report
/path-optimizer restore
```

---

*Faster shell, faster you*
