---
name: code-reviewer
description: Review pull requests for code quality and security issues.
allowed-tools:
  - Read
  - Grep
  - Glob
---

## Overview

This skill helps you review pull requests for code quality, security vulnerabilities,
and adherence to team coding standards.

## Usage

1. Open the pull request diff.
2. Use `Read` to examine changed files.
3. Use `Grep` to search for known anti-patterns.
4. Summarize findings in a structured review comment.

## What to look for

- SQL injection patterns (string interpolation in queries)
- Hardcoded secrets or API keys
- Missing input validation
- Overly broad exception handling
- Unused imports or dead code

## Output format

Provide a structured review with:
- **Summary**: one-sentence overall assessment
- **Issues**: numbered list with file, line, severity, and recommendation
- **Approved**: yes/no with rationale
