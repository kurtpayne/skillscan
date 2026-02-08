# Comprehensive Examples

SkillScan ships a full showcase in `examples/showcase` to demonstrate detection coverage.

## Coverage map

| Example | What it demonstrates | Expected signal |
|---|---|---|
| `01_download_execute` | Download-and-execute chain | `MAL-001` |
| `02_base64_exec` | Decode-and-execute chain | `MAL-002` |
| `03_instruction_abuse` | Coercive prerequisite text | `ABU-001` |
| `04_secret_access` | Secret file markers | `EXF-001` |
| `05_ioc_match` | IOC blocklist matches | `IOC-001` |
| `06_dep_vuln_python` | Vulnerable Python dependency | `DEP-001` |
| `07_dep_vuln_npm` | Vulnerable npm dependency | `DEP-001` |
| `08_unpinned_deps` | Unpinned dependency specs | `DEP-UNPIN` |
| `09_policy_block_domain` | Policy-based domain block | `POL-IOC-BLOCK` |
| `10_openai_style` | OpenAI-style ecosystem hint | `openai_style` |
| `11_claude_style` | Claude-style ecosystem hint | `claude_style` |
| `12_benign_minimal` | Clean baseline sample | no high-severity findings |

## Commands

```bash
skillscan scan examples/showcase/01_download_execute --fail-on never
skillscan scan examples/showcase/05_ioc_match --fail-on never
skillscan scan examples/showcase/09_policy_block_domain --policy examples/policies/showcase_block_domain.yaml --fail-on never
```

For a single-page summary, see `examples/showcase/INDEX.md`.

Each triggered finding in these examples includes an in-report `mitigation` field with recommended remediation steps.
