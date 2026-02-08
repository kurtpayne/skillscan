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

## Run examples

```bash
skillscan scan examples/showcase/01_download_execute --fail-on never
skillscan scan examples/showcase/05_ioc_match --fail-on never
skillscan scan examples/showcase/09_policy_block_domain --policy examples/policies/showcase_block_domain.yaml --fail-on never
```
