# SkillScan Security

**Security scanner for AI agent skills and MCP tool bundles.** Detects prompt injection, malware patterns, IOC matches, supply chain risks, and skill graph vulnerabilities before they reach your agents.

Works with skills from [skills.sh](https://skills.sh), [ClawHub](https://clawhub.ai), and any `SKILL.md`-based or MCP-compatible skill package.

## Quick Start

```bash
# Scan a skills directory
docker run --rm -v "$PWD:/work" kurtpayne/skillscan-security scan /work/skills/

# Include ML-based prompt injection detection
docker run --rm -v "$PWD:/work" kurtpayne/skillscan-security scan /work/skills/ --ml-detect

# Include skill graph analysis (remote .md loads, tool grant escalation, memory poisoning)
docker run --rm -v "$PWD:/work" kurtpayne/skillscan-security scan /work/skills/ --graph

# JSON output for CI / SARIF upload
docker run --rm -v "$PWD:/work" kurtpayne/skillscan-security scan /work/skills/ --format json
docker run --rm -v "$PWD:/work" kurtpayne/skillscan-security scan /work/skills/ --format sarif
```

## Example Output

```
╭─────────────────────────────── Verdict: BLOCK ───────────────────────────────╮
│ Target: skills/data-exfil-skill                                               │
│ Policy: strict                                                                │
│ Score: 85                                                                     │
│ Findings: 3                                                                   │
╰───────────────────────────────────────────────────────────────────────────────╯

Top Findings:
  PINJ-001  CRITICAL  Prompt injection: instruction override attempt
  PINJ-GRAPH-001  HIGH  Skill loads remote .md file at runtime (dead-drop pattern)
  IOC-IP-001  HIGH  Known malicious IP referenced: 185.220.101.47
```

## Detection Capabilities

**Prompt injection (`PINJ-*`):** instruction override, role confusion, jailbreak patterns, Unicode homoglyph attacks, zero-width character injection, base64-encoded instructions, action chain abuse.

**Skill graph (`PINJ-GRAPH-*`, `--graph` flag):** remote `.md` instruction loading, tool grant escalation without declared purpose, memory file poisoning (`SOUL.md`, `MEMORY.md`, `AGENTS.md`).

**IOC matching:** known malicious IPs, domains, and URLs from the SkillScan threat intel feed, updated automatically on each scan.

**Supply chain:** unpinned dependency versions, binary artifacts, executable blobs, compromised package patterns.

**ML detection (`--ml-detect`):** DeBERTa-based classifier fine-tuned on 100+ real injection examples. Downloads the model on first use (~45MB).

## Policy Profiles

```bash
# Strict (default) — block on any HIGH or CRITICAL finding
docker run --rm -v "$PWD:/work" kurtpayne/skillscan-security scan /work --policy strict

# Balanced — block on CRITICAL only
docker run --rm -v "$PWD:/work" kurtpayne/skillscan-security scan /work --policy balanced

# Custom policy file
docker run --rm -v "$PWD:/work" kurtpayne/skillscan-security scan /work \
  --policy /work/my-policy.yaml
```

## CI Integration

```yaml
# GitHub Actions with SARIF upload to Security tab
jobs:
  skillscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan skills
        run: |
          docker run --rm -v "${{ github.workspace }}:/work" \
            kurtpayne/skillscan-security scan /work/skills/ \
            --format sarif > skillscan.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skillscan.sarif
```

Or use the reusable workflow:

```yaml
jobs:
  skillscan:
    uses: kurtpayne/skillscan-security/.github/workflows/skillscan-reusable.yml@main
    with:
      scan-path: ./skills
```

## Intel Management

The scanner ships with a built-in threat intel feed covering 100+ rules and 10+ IOCs, updated automatically. You can also add custom intel sources:

```bash
docker run --rm -v "$PWD:/work" -v "$HOME/.skillscan:/root/.skillscan" \
  kurtpayne/skillscan-security intel sync
```

## Model Sync

The ML classifier model is downloaded on first use. To pre-pull it:

```bash
docker run --rm -v "$HOME/.skillscan:/root/.skillscan" \
  kurtpayne/skillscan-security model sync
```

## Related

- **[skillscan-lint](https://hub.docker.com/r/kurtpayne/skillscan-lint)** — Quality linter: readability, clarity, graph integrity
- **[skills.sh](https://skills.sh)** — Community registry of AI agent skills
- **[GitHub](https://github.com/kurtpayne/skillscan-security)** — Source code, rules, and threat intel
- **[PyPI](https://pypi.org/project/skillscan-security/)** — `pip install skillscan-security`
