---
name: sentence-case
description: Use when writing or reviewing UI copy — buttons, labels, nav items, tooltips, error messages, CTAs, modal text — where sentence case should be enforced instead of title case.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: tuckerschreiber/sentence-case
# corpus-url: https://github.com/tuckerschreiber/sentence-case/blob/93f9b0c709829a10b2958618c5594eb3a49ad9ff/SKILL.md
# corpus-round: 2026-03-19
# corpus-format: markdown_fm
---

# Sentence Case

## Overview

UI copy uses sentence case by default. Auto-correct violations silently when writing copy. When invoked explicitly via `/sentence-case`, audit and rewrite all violations in the target file(s).

## Judgment Framework

**Always sentence case:**
- Buttons: "Get started", "Sign in", "Learn more", "Try for free"
- Form labels: "Email address", "First name", "Date of birth"
- Error/success messages: "Something went wrong", "Changes saved"
- Tooltips and helper text
- Modal titles: "Are you sure?", "Delete this item?"
- Toast notifications: "Link copied to clipboard"
- Nav items (common nouns): "Settings", "Dashboard", "Billing"
- Page and section headings (by default)

**Always preserve as-is:**
- Brand names and trademarks: "Stripe", "GitHub", "macOS", "iPhone", "YouTube"
- Proper nouns: company names, product names, people, places
- Quoted titles of books, films, songs
- Legal document titles

**Config overrides** (check `.sentence-case.md` in project root if present):
- Feature names designated as proper nouns by the team
- Brand exceptions declared explicitly
- Deliberate title-case choices the team has locked in

## Passive Mode (Always Active)

When writing or modifying any UI copy, silently apply sentence case before outputting. Do not announce corrections unless asked.

**Examples:**

| Wrong | Right |
|-------|-------|
| Get Started | Get started |
| Sign In | Sign in |
| Learn More | Learn more |
| First Name | First name |
| Something Went Wrong | Something went wrong |
| Delete Account | Delete account |
| Your Profile | Your profile |

**Do NOT change:**
- "Sign in with GitHub" — GitHub is a proper noun
- "Powered by Stripe" — brand name
- "macOS Monterey" — proper noun
- "iPhone settings" — iPhone is a trademark

## Active Mode (`/sentence-case`)

When invoked explicitly:

1. Check for `.sentence-case.md` in project root — read exceptions if present
2. Scan target file(s) or selection
3. Report each violation: original → corrected + one-line reason
4. Rewrite all violations

Use `/sentence-case audit` to scan all UI copy in the project — look in component files, templates, string files, and i18n files.

## Config File (`.sentence-case.md`)

Optional. Place in project root. Declare exceptions in plain markdown:

```markdown
# Sentence Case Exceptions

## Brand names (always preserve)
- Acme Pro
- SuperWidget

## Deliberate title case (team decision)
- "Get Started" — primary CTA, brand choice

## Feature names treated as proper nouns
- Advanced Analytics
- Smart Sync
```

## Common Mistakes

| Wrong | Right | Context |
|-------|-------|---------|
| Get Started | Get started | Button |
| Sign In | Sign in | Button / nav |
| Learn More | Learn more | CTA |
| First Name | First name | Form label |
| Something Went Wrong | Something went wrong | Error message |
| Are You Sure? | Are you sure? | Modal title |
| View All | View all | Link / button |
| Save Changes | Save changes | Button |