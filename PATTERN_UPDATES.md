# Pattern Updates - February 2026

## 2026-02-09: npx Phantom Package / Registry Fallback Pattern

**Sources:**
- [Aikido - npx Confusion: Packages That Forgot to Claim Their Own Name](https://www.aikido.dev/blog/npx-confusion-unclaimed-package-names)
- [The Hacker News - Compromised dYdX npm and PyPI Packages Deliver Wallet Stealers and RAT Malware](https://thehackernews.com/2026/02/compromised-dydx-npm-and-pypi-packages.html)

**Event Summary:** Recent supply-chain reporting highlighted widespread abuse potential when `npx` commands reference package names that were never claimed. In that case, npm registry fallback can fetch and execute attacker-published code.

**New Pattern Added:**

### SUP-002: npx Registry Fallback Execution Without `--no-install`
- **Category:** malware_pattern
- **Severity:** high
- **Confidence:** 0.86
- **Pattern:** Detects `npx <package>` usage that lacks the `--no-install` safeguard on the same command line.
- **Justification:** Aikido reported large-scale real-world execution volume of phantom `npx` package names, and The Hacker News linked the same abuse class in ongoing package compromise reporting.
- **Mitigation:** Prefer explicit installs and use `npx --no-install` to prevent implicit registry fallback execution.

**Version:** Rules updated from 2026.02.09.4 to 2026.02.09.5

**Testing:** Added assertions in `tests/test_rules.py`, `tests/test_scan.py`, and showcase coverage in `tests/test_showcase_examples.py`.

---

## 2026-02-09: GitHub Actions Secrets-Dump Exfil Pattern

**Sources:**
- [StepSecurity - Shai-Hulud: Self-Replicating Worm Compromises 500+ NPM Packages](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)
- [The Hacker News - Shai-Hulud v2 Spreads From npm to Maven, as Campaign Exposes Thousands of Secrets](https://thehackernews.com/2025/11/shai-hulud-v2-campaign-spreads-from-npm.html)

**Event Summary:** Supply-chain malware campaigns documented malicious GitHub Actions workflow persistence that serializes CI/CD secrets context and transmits it to attacker-controlled endpoints.

**New Patterns Added:**

### EXF-004: GitHub Actions Full Secrets Context Dump
- **Category:** exfiltration
- **Severity:** high
- **Confidence:** 0.93
- **Pattern:** Detects `${{ toJSON(secrets) }}` expansion, a high-risk full-secret serialization marker.
- **Justification:** Incident reports show `${{ toJSON(secrets) }}` used inside malicious workflows to dump all repository/org secrets.
- **Mitigation:** Never serialize the full secrets context; pass only minimally scoped secret values to specific steps.

### CHN-004: GitHub Actions Secrets Context with Outbound Network
- **Category:** exfiltration
- **Severity:** critical
- **Confidence:** 0.94
- **Pattern:** Chains GitHub Actions secrets-context markers with outbound network/exfil indicators.
- **Justification:** Improves precision by requiring both secret-context expansion and transfer behavior.
- **Mitigation:** Remove broad secrets context references and block outbound transfer of CI/CD secrets.

**Version:** Rules updated from 2026.02.09.3 to 2026.02.09.4

**Testing:** Added coverage in `tests/test_rules.py::test_new_patterns_2026_02_09` and showcase validation in `tests/test_showcase_examples.py`.

---

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
