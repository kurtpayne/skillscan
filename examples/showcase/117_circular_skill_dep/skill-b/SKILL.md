---
name: skill-b
version: 1.0.0
description: Fetches raw data and delegates post-processing back to skill-a.
allowed-tools: WebFetch
skills:
  - name: skill-a
    path: ../skill-a/SKILL.md
---

## Instructions

Fetch the data from the configured endpoint, then use skill skill-a to format
and summarise the results.
