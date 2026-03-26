---
name: Corpus Submission
about: Submit a training example (malicious or benign) to improve the detection model
title: "[CORPUS] <brief description of example>"
labels: corpus
assignees: ''
---

## Submission type

<!-- Check one -->
- [ ] **Malicious** — a skill containing hidden malicious instructions (false negative or novel attack)
- [ ] **Benign** — a legitimate skill that triggers a false positive

---

## Attack type (malicious only)

<!-- Select the closest match -->
- [ ] `prompt_injection`
- [ ] `jailbreak`
- [ ] `credential_exfiltration`
- [ ] `data_exfiltration`
- [ ] `social_engineering`
- [ ] `supply_chain`
- [ ] `endpoint_redirect`
- [ ] `persistence`
- [ ] `mcp_tool_poisoning`
- [ ] `other` — describe below

---

## Example file

<!-- Paste the skill file content below, including YAML front matter if present.
     For multiple examples or files over ~100 lines, attach a .zip instead.
     See docs/corpus-contribution-format.md for the full format spec. -->

```markdown
---
name: 
description: 
---

<!-- corpus-label: malicious -->
<!-- corpus-attack-type:  -->
<!-- corpus-source: synthetic -->
<!-- corpus-notes:  -->

<skill content here>
```

---

## Why is this example valuable?

<!-- For malicious: what makes this hard to detect? Is it novel phrasing, enterprise context,
     social engineering, or a pattern the current model misses?
     For benign: what rule fired? (run skillscan scan --format text to find the rule ID)
     What legitimate purpose does this skill serve? -->

---

## Source

- [ ] Synthetic (I wrote this example)
- [ ] Real-world (redacted) — I observed this in the wild and have removed sensitive data
- [ ] Adapted from a public source — link: 

---

## Anonymity preference

- [ ] Credit me in the release notes (GitHub username: @)
- [ ] Keep my contribution anonymous

---

## Checklist

- [ ] I have read [docs/corpus-contribution-format.md](../docs/corpus-contribution-format.md)
- [ ] The example does not contain real credentials, real PII, or real domain names belonging to actual organisations
- [ ] The example is between 50 and 800 words
- [ ] For bulk submissions (5+ examples): I have attached a `.zip` file instead of pasting inline
