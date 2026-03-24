# SkillScan Rule Examples

> Auto-generated from `src/skillscan/data/rules/`. Do not edit by hand.
> Run `python3 scripts/generate_examples_table.py` to regenerate.

**2 static rules · 15 chain rules**

## Static Rules

### Malware & Execution

| ID | Severity | Title | Tags |
|---|---|---|---|
| `AST-001` | critical | Constructed input reaches execution sink |  |

### Exfiltration

| ID | Severity | Title | Tags |
|---|---|---|---|
| `AST-002` | critical | Potential secret data sent to network sink |  |
| `MAL-042` | critical | CanisterWorm Kubernetes wiper with geopolitical targeting | malware_pattern, mal, kubernetes, wiper |
| `EXEC-041` | high | API traffic hijacking via AI agent settings override | exfiltration, exec, api-hijack |

## Chain Rules

| ID | Severity | Title | Requires | Tags |
|---|---|---|---|---|
| `ABU-002` | high | Elevated setup with security bypass | `privilege + security_disable` | privilege-escalation, defense-evasion, setup-abuse |
| `CHN-001` | critical | Dangerous action chain: download plus execute | `download + execute` | malware, download-execute, dropper |
| `CHN-002` | critical | Potential secret exfiltration chain | `secret_access + network` | exfiltration, credential-theft, network |
| `CHN-003` | critical | Potential secret exfiltration via alternate channel | `secret_access + exfil_channel` | exfiltration, covert-channel, dns-exfil, credential-theft |
| `CHN-004` | critical | GitHub Actions secrets context with outbound network | `gh_actions_secrets + network` | ci-cd, github-actions, exfiltration, secrets |
| `CHN-005` | critical | pull_request_target with untrusted PR head checkout | `gh_pr_target + gh_pr_head_checkout` | ci-cd, github-actions, pwn-requests, supply-chain |
| `CHN-006` | critical | pull_request_target with untrusted PR metadata in shell/script | `gh_pr_target + gh_pr_untrusted_meta` | ci-cd, github-actions, injection, pwn-requests |
| `CHN-007` | critical | pull_request_target with untrusted PR-derived Actions cache key | `gh_pr_target + gh_cache_untrusted_key` | ci-cd, github-actions, cache-poisoning, supply-chain |
| `CHN-008` | critical | pull_request_target with unpinned third-party GitHub Action | `gh_pr_target + gh_unpinned_action_ref` | ci-cd, github-actions, supply-chain, unpinned-dependency |
| `CHN-009` | high | Repository hook configuration with shell-command payload | `claude_hooks_marker + hook_shell_command_field` | hook-abuse, persistence, shell-execution, claude-code |
| `CHN-010` | critical | pull_request_target with branch/ref metadata interpolation in shell/script | `gh_pr_target + gh_pr_ref_meta` | ci-cd, github-actions, injection, pwn-requests |
| `CHN-011` | critical | MCP tool poisoning with credential exfiltration chain | `mcp_tool_poison + secret_access` | mcp, tool-poisoning, exfiltration, credential-theft |
| `CHN-012` | critical | Stealth concealment with network exfiltration chain | `stealth_conceal + network` | stealth, exfiltration, covert-channel, deception |
| `CHN-013` | critical | Container escape with host path mount chain | `container_escape + host_path_mount` | container-escape, privilege-escalation, host-compromise |
| `CHN-014` | critical | Container escape with secret access chain | `container_escape + secret_access` | container-escape, credential-theft, privilege-escalation |
| `MAL-043` | high | SANDWORM_MODE npm worm with McpInject AI toolchain poisoning | `100_sandworm_mode_npm_worm` | supply-chain, npm-worm, mcp-poisoning, credential-theft, ai-toolchain |
| `PINJ-005` | high | Clinejection indirect prompt injection via external data fields | `101_clinejection_indirect_prompt_injection` | prompt-injection, indirect-injection, ai-agent, supply-chain, lateral-movement |
| `SUP-014` | high | Azure MCP Server SSRF privilege escalation (CVE-2026-26118) | `102_azure_mcp_ssrf_privilege_escalation` | azure, mcp-server, ssrf, privilege-escalation, cve |
| `MAL-044` | critical | SQLBot stored prompt injection to RCE via COPY TO PROGRAM | `104_sqlbot_prompt_injection_rce` | prompt-injection, rce, sql, postgres, ai-agent, cve |
| `PINJ-006` | high | RAG poisoning multi-stage AI agent attack chain | `105_rag_poisoning_attack_chain` | rag, prompt-injection, ai-agent, knowledge-base, data-poisoning |
| `SUP-015` | critical | GitHub Actions supply chain compromise via release tag repointing | `106_github_actions_tag_repointing` | github-actions, supply-chain, tag-repointing, credential-theft, trivy |
| `MAL-045` | high | StoatWaffle Node.js malware family (WaterPlum/Contagious Interview) | `107_stoatwaffle_vscode_malware` | malware, nodejs, stoatwaffle, waterplum, contagious-interview, vscode, rat, stealer |
| `SUP-016` | high | Vulnerable MCP server package with command injection | `108_mcp_server_command_injection_cve` | mcp, supply-chain, command-injection, rce, cve, vulnerability |
| `MAL-048` | critical | Langflow unauthenticated RCE via build_public_tmp endpoint (CVE-2026-33017) | `100_langflow_rce_build_public_tmp` | langflow, rce, cve, ai-pipeline, unauthenticated, supply-chain |
| `SUP-017` | critical | Checkmarx GitHub Actions supply chain compromise (TeamPCP, CVE-2026-33634) | `101_checkmarx_actions_teampcp` | supply-chain, github-actions, checkmarx, teampcp, credential-theft, tag-repointing |
