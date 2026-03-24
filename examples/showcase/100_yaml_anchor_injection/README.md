# YAML Anchor/Alias Injection in Skill Frontmatter (PINJ-008)

## Attack Overview

YAML anchor (`&anchor`) and alias (`*alias`) syntax in non-standard frontmatter fields can inject hidden instruction blocks that override a skill's declared behavior. The attack works because YAML parsers resolve aliases transparently — the `base_instructions: *override` line silently inherits the full `system_override` block, which sets `role: unrestricted assistant` and disables safety filters.

This attack is particularly dangerous because:
- It is invisible in rendered Markdown (GitHub, docs sites) — only visible in raw YAML
- The override fields look like legitimate configuration keys to a casual reviewer
- A single anchor can be aliased multiple times, affecting multiple configuration sections

## Attack Chain

1. Attacker creates a skill that appears to be a legitimate Azure deployment helper
2. Frontmatter contains `system_override: &override` with malicious role/restriction overrides
3. `base_instructions: *override` and `override_context: *override` silently inherit the override
4. When the skill is loaded, the model's role and safety configuration are replaced

## Expected Findings

| Rule | Severity | Confidence |
|------|----------|------------|
| PINJ-008 | High | High |

## References

- [YAML Anchor Injection — OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Prompt Injection via Configuration Files](https://atlas.mitre.org/techniques/AML.T0051)
