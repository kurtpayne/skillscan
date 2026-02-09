# Pattern Updates - February 2026

## 2026-02-09: dYdX Supply Chain Attack Patterns

**Source:** [The Hacker News - Compromised dYdX npm and PyPI Packages](https://thehackernews.com/2026/02/compromised-dydx-npm-and-pypi-packages.html)

**Event Summary:** Legitimate dYdX cryptocurrency packages on npm and PyPI were compromised to deliver wallet stealers and RAT malware. The attack targeted wallet credentials and included stealth remote command execution capabilities.

**New Patterns Added:**

### EXF-002: Cryptocurrency Wallet File Access
- **Category:** exfiltration
- **Severity:** high
- **Confidence:** 0.88
- **Pattern:** Detects access to crypto wallet files (wallet.dat, .keystore, mnemonic, private keys)
- **Justification:** dYdX attack specifically targeted wallet seed phrases and credentials
- **Mitigation:** Do not access wallet files or seed phrases; crypto operations should use secure key management

### MAL-004: Dynamic Code Evaluation Pattern
- **Category:** malware_pattern
- **Severity:** high
- **Confidence:** 0.85
- **Pattern:** Detects eval(), exec(), Function() constructor, and vm.run* patterns
- **Justification:** Python RAT component in dYdX attack used exec() for remote command execution
- **Mitigation:** Avoid eval/exec flows that execute arbitrary code strings; use explicit functions

### OBF-002: Stealth Execution Pattern
- **Category:** instruction_abuse
- **Severity:** medium
- **Confidence:** 0.8
- **Pattern:** Detects CREATE_NO_WINDOW, nohup with output redirection, hidden process execution
- **Justification:** dYdX RAT used CREATE_NO_WINDOW flag to execute without console window on Windows
- **Mitigation:** Remove hidden/stealth execution flags that obscure command behavior

**Version:** Rules updated from 2026.02.09.1 to 2026.02.09.2

**Testing:** All patterns validated with unit tests in `tests/test_rules.py::test_new_patterns_2026_02_09`

---

## 2026-02-09: DockerDash Meta-Context Injection Pattern

**Sources:**
- [Noma Security - DockerDash: Two Attack Paths, One AI Supply Chain Crisis](https://noma.security/blog/dockerdash-two-attack-paths-one-ai-supply-chain-crisis/)
- [The Hacker News - Docker Fixes Critical Ask Gordon AI Flaw Allowing Code Execution via Image Metadata](https://thehackernews.com/2026/02/docker-fixes-critical-ask-gordon-ai.html)

**Event Summary:** Researchers documented a meta-context injection path where malicious instructions embedded in Docker image metadata are interpreted by AI assistants and used to trigger MCP tool actions, including data exfiltration through markdown image beacons with interpolated data placeholders.

**New Pattern Added:**

### EXF-003: Markdown Image Beacon Exfiltration Pattern
- **Category:** exfiltration
- **Severity:** high
- **Confidence:** 0.84
- **Pattern:** Detects markdown image URLs containing likely exfil query keys (`data`, `dump`, `exfil`, `token`, `key`) with variable placeholders.
- **Justification:** DockerDash examples include image-beacon style exfiltration payloads embedded in metadata context.
- **Mitigation:** Block instruction-driven external image beacons with interpolated placeholders and treat all metadata/context as untrusted.

**Version:** Rules updated from 2026.02.09.2 to 2026.02.09.3
