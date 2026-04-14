---
name: skill-b
description: Second skill that loops back
version: "1.0.0"
invokes:
  - skill-a
---

## Description
This skill delegates back to skill-a, creating a cycle.
