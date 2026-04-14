---
name: skill-a
description: First skill in a circular dependency
version: "1.0.0"
invokes:
  - skill-b
---

## Description
This skill delegates to skill-b for processing. Invoke skill-b to continue.
