# SkillScan Detection Showcase

Each folder demonstrates one major detection or behavior.

1. `01_download_execute`: expects `MAL-001` (strict => `block`)
2. `02_base64_exec`: expects `MAL-002` (strict => `block` from score)
3. `03_instruction_abuse`: expects `ABU-001` (strict => `block` from score)
4. `04_secret_access`: expects `EXF-001` (strict => `block` from score)
5. `05_ioc_match`: expects `IOC-001` (strict hard-block)
6. `06_dep_vuln_python`: expects `DEP-001`
7. `07_dep_vuln_npm`: expects `DEP-001`
8. `08_unpinned_deps`: expects `DEP-UNPIN`
9. `09_policy_block_domain`: expects `POL-IOC-BLOCK` with custom policy
10. `10_openai_style`: ecosystem hint `openai_style`
11. `11_claude_style`: ecosystem hint `claude_style`
12. `12_benign_minimal`: expected clean/low-risk baseline
13. `13_zero_width_evasion`: unicode-normalized instruction detection (`ABU-001`)
14. `14_base64_hidden_chain`: decoded hidden chain detection (`CHN-001`)
15. `15_secret_network_chain`: secret-to-network chain detection (`CHN-002`)
16. `16_privilege_disable_chain`: privilege+security bypass chain (`ABU-002`)
17. `17_defanged_ioc`: defanged IOC normalization and extraction
18. `18_split_base64_chain`: split base64 fragment decoding (`CHN-001`)
19. `19_alt_download_exec`: alternate download+execute action chain (`CHN-001`)
20. `20_ai_semantic_risk`: semantic credential-harvest wording (detected via `--ai-assist`)
21. `21_npm_lifecycle_abuse`: malicious npm lifecycle bootstrap (`SUP-001`)
22. `22_prompt_injection`: instruction override/jailbreak patterns (`PINJ-001`)
23. `23_trojan_source_bidi`: bidi Unicode obfuscation markers (`OBF-001`)
24. `24_binary_artifact`: executable binary artifact classification (`BIN-001`)
25. `25_wallet_eval_stealth`: wallet-targeting + dynamic eval + stealth execution markers (`EXF-002`, `MAL-004`, `OBF-002`)
26. `26_metadata_image_beacon`: metadata-injected markdown image beacon with interpolated exfil marker (`EXF-003`)

## Run examples

```bash
skillscan scan examples/showcase/01_download_execute --fail-on never
skillscan scan examples/showcase/05_ioc_match --fail-on never
skillscan scan examples/showcase/09_policy_block_domain --policy examples/policies/showcase_block_domain.yaml --fail-on never
skillscan scan examples/showcase/20_ai_semantic_risk --ai-assist --fail-on never
skillscan scan examples/showcase/21_npm_lifecycle_abuse --fail-on never
```
