# SkillScan Rule Examples

> Auto-generated from `src/skillscan/data/rules/`. Do not edit by hand.
> Run `python3 scripts/generate_examples_table.py` to regenerate.

**2 static rules · 14 chain rules**

## Static Rules

### Malware & Execution

| ID | Severity | Title | Tags |
|---|---|---|---|
| `AST-001` | critical | Constructed input reaches execution sink |  |

### Exfiltration

| ID | Severity | Title | Tags |
|---|---|---|---|
| `AST-002` | critical | Potential secret data sent to network sink |  |

## Chain Rules

| ID | Severity | Title | Requires | Tags |
|---|---|---|---|---|
| `CHN-001` | critical | Download + Execute chain | `download + execute` |  |
| `CHN-002` | critical | Secret access + Network exfiltration chain | `secret_access + network` |  |
| `CHN-003` | high | Secret access combined with DNS exfiltration | `secret_access + dns_exfil` |  |
| `CHN-004` | critical | GitHub Actions full secrets context dump + network | `gh_actions_secrets + network` |  |
| `CHN-005` | critical | pull_request_target + untrusted PR-head checkout | `gh_pr_target + gh_pr_head_checkout` |  |
| `CHN-006` | critical | pull_request_target + untrusted PR metadata interpolation | `gh_pr_target + gh_pr_untrusted_meta` |  |
| `CHN-007` | high | pull_request_target + untrusted cache key | `gh_pr_target + gh_cache_untrusted_key` |  |
| `CHN-008` | high | pull_request_target + unpinned third-party action | `gh_pr_target + gh_unpinned_action_ref` |  |
| `CHN-009` | critical | Secret access combined with SMTP exfiltration | `secret_access + smtp_exfil` |  |
| `CHN-010` | high | pull_request_target + PR ref/branch metadata interpolation | `gh_pr_target + gh_pr_ref_meta` |  |
| `CHN-011` | critical | Secret access combined with SCP/rsync exfiltration | `secret_access + scp_exfil` |  |
| `CHN-012` | high | Stealth concealment combined with network exfiltration | `stealth_concealment + network` |  |
| `CHN-013` | critical | Docker socket mount combined with privileged container execution | `docker_socket + privileged_container` |  |
| `CHN-014` | critical | Privileged container execution combined with secret access | `privileged_container + secret_access` |  |

