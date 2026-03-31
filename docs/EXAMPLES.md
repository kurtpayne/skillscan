# SkillScan Rule Examples
> Auto-generated from `src/skillscan/data/rules/`. Do not edit by hand.
> Run `python3 scripts/generate_examples_table.py` to regenerate.

**136 static rules · 14 chain rules**

## Static Rules

### Malware & Execution
| ID | Severity | Title | Tags |
|---|---|---|---|
| `MAL-001` | critical | Download-and-execute chain | malware_pattern, mal |
| `MAL-002` | high | Base64 decode + execution | malware_pattern, mal |
| `MAL-003` | high | Subshell downloader execution pattern | malware_pattern, mal |
| `MAL-004` | high | Dynamic code evaluation pattern | malware_pattern, mal |
| `MAL-051` | critical | Embedded binary or shellcode (base64/hex-encoded executable) | malware, embedded-binary, shellcode, dropper |
| `SUP-002` | high | npx registry fallback execution without --no-install | malware_pattern, sup |
| `SUP-003` | high | Piped sed write to out-of-scope or agent config path | malware_pattern, sup |
| `DEF-001` | critical | Windows Defender exclusion manipulation | malware_pattern, def |
| `MAL-005` | high | mshta.exe remote execution pattern | malware_pattern, mal |
| `MAL-006` | high | PowerShell web request piped to Invoke-Expression | malware_pattern, mal |
| `SUP-004` | high | npm preinstall/postinstall shell bootstrap pattern | malware_pattern, sup |
| `SUP-005` | high | npm preinstall/postinstall inline Node eval pattern | malware_pattern, sup |
| `MAL-007` | high | BYOVD security-killer toolkit marker | malware_pattern, mal |
| `MAL-008` | high | Discord Electron debugger credential interception marker | malware_pattern, mal |
| `EXF-008` | high | GitHub Actions untrusted PR metadata interpolation in run/script | malware_pattern, exf |
| `MAL-010` | high | GitHub Actions issue/comment metadata interpolation in run/script | malware_pattern, mal |
| `MAL-021` | high | GitHub Actions branch/ref metadata interpolation in run/script | malware_pattern, mal |
| `MAL-009` | high | ClickFix DNS nslookup staged command execution pattern | malware_pattern, mal |
| `SUP-006` | high | Dotenv newline environment-variable injection payload marker | malware_pattern, sup |
| `SUP-007` | high | npm preinstall/postinstall global package install pattern | malware_pattern, sup |
| `SUP-008` | high | npm lifecycle mutable @latest dependency install pattern | malware_pattern, sup |
| `SUP-009` | high | Hex-decoded command string execution marker | malware_pattern, sup |
| `MAL-011` | high | pull_request_target workflow using unpinned third-party action ref | malware_pattern, mal |
| `MAL-012` | high | VS Code task autorun-on-folder-open marker | malware_pattern, mal |
| `MAL-013` | high | macOS osascript JavaScript (JXA) execution marker | malware_pattern, mal |
| `MAL-014` | high | Deceptive media/document double-extension LNK masquerade | malware_pattern, mal |
| `MAL-015` | high | Claude Code hooks shell command execution marker | malware_pattern, mal |
| `MAL-016` | high | Pastebin steganographic dead-drop resolver marker | malware_pattern, mal |
| `MAL-017` | high | WebSocket C2 shell execution marker | malware_pattern, mal |
| `MAL-018` | high | node-glob CLI --cmd shell execution sink marker | malware_pattern, mal |
| `MAL-019` | high | StegaBin npm shared payload path marker | malware_pattern, mal |
| `MAL-020` | high | VS Code task off-screen whitespace command padding marker | malware_pattern, mal |
| `MAL-022` | high | Bash parameter-expansion command smuggling marker | malware_pattern, mal |
| `MAL-023` | high | Cross-platform password-harvest credential validation marker | malware_pattern, mal |
| `MAL-024` | high | CloudFormation admin-role bootstrap marker via CAPABILITY_IAM | malware_pattern, mal |
| `MAL-025` | critical | MCP tool description poisoning via hidden instruction block | malware_pattern, mal, mcp |
| `MAL-026` | critical | Docker socket mount or access pattern | malware_pattern, mal, container_escape |
| `MAL-027` | high | Privileged container execution or dangerous capability grant | malware_pattern, mal, container_escape |
| `MAL-028` | high | Host network infrastructure manipulation | malware_pattern, mal, container_escape |
| `MAL-029` | critical | Solana RPC blockchain C2 resolution marker | malware_pattern, mal |
| `MAL-030` | high | IDE deeplink MCP server install abuse | malware_pattern, mal |
| `MAL-031` | high | Deno bring-your-own-runtime execution pattern | malware_pattern, mal |
| `MAL-032` | high | GlassWorm persistence marker variable | malware_pattern, mal |
| `MAL-033` | critical | BlokTrooper VSX extension GitHub-hosted downloader pattern | malware_pattern, mal |
| `MAL-034` | high | Click-Fix WebDAV share mount and execute pattern | malware_pattern, mal |
| `MAL-035` | high | OpenClaw gatewayUrl parameter injection and approval bypass | malware_pattern, mal |
| `MAL-041` | high | Trojanized Electron app.asar C2 payload injection | malware_pattern, mal |
| `MAL-036` | high | AI-gated malware execution via LLM API C2 decision-making | malware_pattern, mal |
| `SUP-010` | high | npm postinstall environment variable exfiltration via webhook or agentmail | malware_pattern, sup |
| `MAL-037` | high | GhostClaw/GhostLoader SKILL.md malware delivery via OpenClaw workflows | malware_pattern, mal |
| `MAL-038` | high | LotAI technique — AI assistant used as covert C2 relay via hidden WebView2 | malware_pattern, mal |
| `SUP-011` | high | Open VSX extensionPack/extensionDependencies transitive dependency attack | malware_pattern, sup |
| `SUP-012` | high | npm dependency chain attack via hollow relay package with postinstall loader | malware_pattern, sup |
| `MAL-039` | critical | GitHub Actions credential stealer with Runner.Worker memory harvesting | malware_pattern, mal |
| `MAL-040` | critical | CanisterWorm npm self-propagating worm with ICP blockchain C2 | malware_pattern, mal |
| `MAL-042` | critical | CanisterWorm Kubernetes wiper with geopolitical targeting | malware_pattern, mal, kubernetes, wiper |
| `MAL-043` | high | SANDWORM_MODE npm worm with McpInject AI toolchain poisoning | supply-chain, npm-worm, mcp-poisoning, credential-theft, ai-toolchain |
| `MAL-044` | critical | SQLBot stored prompt injection to RCE via COPY TO PROGRAM | prompt-injection, rce, sql, postgres, ai-agent, cve |
| `MAL-045` | high | StoatWaffle Node.js malware family (WaterPlum/Contagious Interview) | malware, nodejs, stoatwaffle, waterplum, contagious-interview, vscode, rat, stealer |
| `MAL-046` | critical | CursorJack-style MCP deeplink staged payload | mcp, deeplink, staged-payload, cursorjack, cve, rce |
| `MAL-047` | critical | Claude Code hooks RCE via project settings | claude-code, hooks, mcp, rce, cve, project-settings |
| `MAL-048` | critical | Langflow unauthenticated RCE via build_public_tmp endpoint | langflow, rce, cve, ai-pipeline, unauthenticated, supply-chain |
| `MAL-052` | high | Token/cost harvesting - skill instructs agent to loop or generate excessive output | malware, cost-harvesting, token-burn, denial-of-service |
| `MAL-053` | critical | EICAR test string detected in skill file | malware, eicar, test-artifact, scanner-probe |
| `GR-007` | high | Circular skill dependency detected | graph, circular-dependency, graph-rule |
| `MAL-049` | critical | LiteLLM .pth file persistence and sysmon backdoor (TeamPCP) | supply-chain, litellm, teampcp, pth-persistence, credential-theft, backdoor |
| `MAL-050` | high | Ghost Campaign malicious npm packages (sudo phishing RAT) | malware, npm, ghost-campaign, sudo-phishing, rat, cryptocurrency-theft |
| `MAL-054` | critical | GlassWorm multi-stage Chrome extension RAT | malware_pattern, glassworm, chrome-extension, solana, rat |
| `MAL-055` | critical | postmark-mcp BCC email harvesting (first in-the-wild malicious MCP server) | malware_pattern, mcp-server, email-exfiltration, bcc-injection, postmark, supply-chain |
| `MAL-056` | critical | Nx/s1ngularity AI CLI weaponization via dangerously-skip-permissions | malware_pattern, ai-weaponization, supply-chain, postinstall, nx, s1ngularity |

### Exfiltration
| ID | Severity | Title | Tags |
|---|---|---|---|
| `EXF-001` | high | Sensitive credential file access | exfiltration, exf |
| `EXF-002` | high | Cryptocurrency wallet file access | exfiltration, exf |
| `EXF-003` | high | Markdown image beacon exfiltration pattern | exfiltration, exf |
| `EXF-004` | high | GitHub Actions full secrets context dump | exfiltration, exf |
| `EXF-005` | high | GitHub Actions untrusted PR head checkout reference | exfiltration, exf |
| `EXF-006` | high | IPv4-mapped IPv6 loopback/metadata SSRF bypass literal | exfiltration, exf |
| `EXF-007` | high | OpenClaw gateway token/private-key config access marker | exfiltration, exf |
| `EXF-009` | high | MCP tool hidden credential-harvest prompt block marker | exfiltration, exf |
| `EXF-010` | high | GitHub Actions cache key interpolation from untrusted PR metadata | exfiltration, exf |
| `EXF-011` | high | GitHub Codespaces token file + remote JSON schema exfil marker | exfiltration, exf |
| `EXF-012` | high | Claude Code project env ANTHROPIC_BASE_URL override marker | exfiltration, exf |
| `EXF-013` | high | AI assistant global MCP config injection marker | exfiltration, exf |
| `EXF-014` | high | Bracket-glob obfuscated sensitive path marker | exfiltration, exf |
| `EXF-015` | high | Multi-target developer credential file harvest list marker | exfiltration, exf |
| `EXF-016` | high | Azure MCP resource-identifier URL substitution token-leak marker | exfiltration, exf |
| `EXF-017` | high | OpenClaw agent memory and identity file harvesting | exfiltration, exf |
| `EXEC-041` | high | API traffic hijacking via AI agent settings override | exfiltration, exec, api-hijack |
| `EXF-018` | high | Error message instructed to leak system prompt or conversation history | exfiltration, error-leakage, context-leak, prompt-exfil |
| `EXF-019` | high | Logging or audit endpoint collecting conversation history or environment metadata | exfiltration, logging-abuse, telemetry-exfil, conversation-harvest |
| `EXF-020` | critical | TeamPCP sysmon backdoor Kubernetes lateral movement | exfiltration, teampcp, kubernetes, lateral-movement |

### Instruction Abuse
| ID | Severity | Title | Tags |
|---|---|---|---|
| `ABU-001` | high | Coercive prerequisite wording | instruction_abuse, abu |
| `PINJ-001` | high | Prompt override / jailbreak instruction pattern | instruction_abuse, pinj |
| `OBF-001` | medium | Bidirectional Unicode control character detected | instruction_abuse, obf |
| `OBF-002` | medium | Stealth execution pattern | instruction_abuse, obf |
| `OBF-003` | high | Unicode PUA obfuscation near dynamic execution sink | instruction_abuse, obf |
| `OBF-004` | high | Unicode steganography in skill instructions (zero-width / homoglyph) | instruction_abuse, obf, unicode-steganography, homoglyph |
| `ABU-003` | high | Claude Code project MCP auto-approval marker | instruction_abuse, abu |
| `ABU-004` | high | Tool auto-approve allowlist includes package-install command | instruction_abuse, abu |
| `ABU-005` | high | MCP tool name-collision hijack marker | instruction_abuse, abu |
| `ABU-006` | high | Stealth instruction concealment from user | instruction_abuse, abu, mcp |
| `ABU-007` | high | Cross-server MCP tool invocation instruction | instruction_abuse, abu, mcp |
| `PINJ-002` | high | MCP tool result MEDIA directive injection | instruction_abuse, pinj |
| `PINJ-003` | high | Prompt control persistence via heartbeat file or memory store manipulation | instruction_abuse, pinj |
| `PINJ-004` | high | Claudy Day prompt injection via AI assistant URL parameter and data exfiltration | instruction_abuse, pinj |
| `PINJ-005` | high | Clinejection indirect prompt injection via external data fields | prompt-injection, indirect-injection, ai-agent, supply-chain, lateral-movement |
| `OBF-005` | high | Covert-channel exfiltration via DNS, whitespace encoding, or HTML comments | instruction_abuse, covert-channel, dns-exfil, steganography, html-comment-injection |
| `CAP-001` | high | Capability laundering — disproportionate credential or file access for stated purpose | instruction_abuse, capability-laundering, credential-access, over-privileged |

### Supply Chain
| ID | Severity | Title | Tags |
|---|---|---|---|
| `SUP-013` | high | MCP server command injection via unsanitized Git parameters | supply_chain, sup |
| `SUP-014` | high | Azure MCP Server SSRF privilege escalation (CVE-2026-26118) | azure, mcp-server, ssrf, privilege-escalation, cve |
| `SUP-015` | critical | GitHub Actions supply chain compromise via release tag repointing | github-actions, supply-chain, tag-repointing, credential-theft, trivy |
| `SUP-016` | high | Vulnerable MCP server package with command injection | mcp, supply-chain, command-injection, rce, cve, vulnerability |
| `SUP-017` | critical | Checkmarx GitHub Actions supply chain compromise (TeamPCP) | supply-chain, github-actions, checkmarx, teampcp, credential-theft, tag-repointing |
| `SUP-018` | medium | pip install in skill body with non-standard or suspicious package name | supply-chain, pip-install, runtime-dependency, typosquatting |
| `SUP-019` | critical | Compromised LiteLLM package version reference | supply-chain, litellm, teampcp, compromised-package, credential-theft |
| `SUP-020` | high | ClawHavoc malicious ClawHub skill typosquat names | supply-chain, clawhavoc, typosquat, openclaw, clawhub |
| `SUP-021` | critical | TeamPCP Checkmarx VS Code extension compromise (Open VSX) | supply-chain, vscode-extension, teampcp, open-vsx, infostealer |
| `SUP-022` | high | React Native npm account takeover supply chain attack | supply-chain, npm, account-takeover, react-native, dependency-chain |
| `SUP-023` | critical | mcp-remote OAuth authorization_endpoint command injection (CVE-2025-6514) | supply-chain, mcp, cve, oauth, command-injection, rce |
| `SUP-001` | critical | npm lifecycle script pipes remote content to shell | supply_chain, sup, npm, lifecycle-script |

### social_engineering
| ID | Severity | Title | Tags |
|---|---|---|---|
| `SE-001` | high | Social engineering credential harvest instruction | social_engineering, credential_harvest, instruction_abuse |
| `SE-003` | critical | Prize or reward scam with credential or account request | social-engineering, prize-scam, credential-harvest, phishing, reward-fraud |
| `SE-002` | high | Git credential file harvest combined with send or upload instruction | social-engineering, credential-harvest, git-credentials, exfiltration |

### prompt_injection
| ID | Severity | Title | Tags |
|---|---|---|---|
| `PINJ-006` | high | RAG poisoning multi-stage AI agent attack chain | rag, prompt-injection, ai-agent, knowledge-base, data-poisoning |
| `PINJ-007` | high | MCP sampling-based context exfiltration | mcp, sampling, prompt-injection, context-exfiltration, indirect-injection |
| `PINJ-008` | high | YAML anchor/alias injection in skill frontmatter | prompt-injection, yaml-injection, frontmatter, anchor-alias |
| `PINJ-009` | high | Fake end-of-prompt divider injection | prompt-injection, divider-injection, context-reset, instruction-override |
| `PINJ-010` | critical | Fake system header before skill frontmatter | prompt-injection, system-header-spoofing, role-override, instruction-override |
| `PINJ-012` | critical | AGENT INSTRUCTION block injection | prompt-injection, covert-instructions, agent-hijacking, hidden-directives |
| `PINJ-011` | high | Tool alias injection mapping safe name to dangerous tool | prompt-injection, tool-alias, instruction-abuse |
| `PINJ-013` | high | Conditional time-lock with instruction override | prompt-injection, time-lock, conditional-payload, delayed-activation |
| `PINJ-014` | high | Injection keyword in non-description frontmatter field | prompt-injection, frontmatter-injection, metadata-injection |
| `PINJ-015` | high | Prompt poaching via malicious browser extension installation | prompt-injection, browser-extension, prompt-poaching, data-theft |
| `PINJ-016` | high | AI documentation context poisoning (ContextHub) | prompt_injection, documentation-poisoning, contexthub |

### permission_scope
| ID | Severity | Title | Tags |
|---|---|---|---|
| `PSV-001` | medium | Skill instructions imply network access not declared in allowed-tools | permission-scope, network, graph-rule |
| `PSV-002` | medium | Skill instructions imply filesystem write not declared in allowed-tools | permission-scope, filesystem, graph-rule |
| `PSV-003` | high | Skill instructions imply shell execution not declared in allowed-tools | permission-scope, shell, graph-rule |
| `PSV-004` | medium | Unknown frontmatter key may be an injection vector | permission-scope, frontmatter, graph-rule |
| `PSV-005` | medium | Capability inflation - skill claims wildcard or all-scope permissions | permission-scope, capability-inflation, least-privilege |

### abuse
| ID | Severity | Title | Tags |
|---|---|---|---|
| `ABU-002` | high | Privilege escalation combined with security control disable | instruction_abuse, abu, privilege-escalation |

## Chain Rules
| ID | Severity | Title | Requires | Tags |
|---|---|---|---|---|
| `CHN-001` | critical | Download + Execute chain | `download + execute` |  |
| `CHN-002` | critical | Secret access + Network exfiltration chain | `network + secret_access` |  |
| `CHN-003` | high | Secret access combined with DNS exfiltration | `dns_exfil + secret_access` |  |
| `CHN-004` | critical | GitHub Actions full secrets context dump + network | `gh_actions_secrets + network` |  |
| `CHN-005` | critical | pull_request_target + untrusted PR-head checkout | `gh_pr_head_checkout + gh_pr_target` |  |
| `CHN-006` | critical | pull_request_target + untrusted PR metadata interpolation | `gh_pr_target + gh_pr_untrusted_meta` |  |
| `CHN-007` | high | pull_request_target + untrusted cache key | `gh_cache_untrusted_key + gh_pr_target` |  |
| `CHN-008` | high | pull_request_target + unpinned third-party action | `gh_pr_target + gh_unpinned_action_ref` |  |
| `CHN-010` | high | pull_request_target + PR ref/branch metadata interpolation | `gh_pr_ref_meta + gh_pr_target` |  |
| `CHN-009` | critical | Secret access combined with SMTP exfiltration | `secret_access + smtp_exfil` |  |
| `CHN-011` | critical | Secret access combined with SCP/rsync exfiltration | `scp_exfil + secret_access` |  |
| `CHN-012` | high | Stealth concealment combined with network exfiltration | `network + stealth_concealment` |  |
| `CHN-013` | critical | Docker socket mount combined with privileged container execution | `docker_socket + privileged_container` |  |
| `CHN-014` | critical | Privileged container execution combined with secret access | `privileged_container + secret_access` |  |
