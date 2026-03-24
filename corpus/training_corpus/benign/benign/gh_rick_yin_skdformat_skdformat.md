---
name: skdformat
description: ShanghaiTech graduate thesis formatting, structure checking, and LaTeX implementation with shtthesis. Use when creating, linting, fixing, or migrating a ShanghaiTech thesis or dissertation, especially for LaTeX projects that need compliant covers, abstracts, table of contents, chapter structure, references, appendices, blind-review builds, or print-ready output.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: Rick-Yin/skdformat
# corpus-url: https://github.com/Rick-Yin/skdformat/blob/4e17faa8799b73f0151778bce667c8073561d934/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# skdformat

## Overview

Use this skill to create or audit ShanghaiTech thesis documents. Treat the bundled reference as the source of truth, and treat `shtthesis` as the preferred LaTeX implementation layer rather than a replacement for the rules.

Read [references/shanghaitech-thesis-format.md](references/shanghaitech-thesis-format.md) for exact requirements. For a new self-contained LaTeX project, also read [references/thesis-starter.tex](references/thesis-starter.tex), [references/build-thesis-example.ps1](references/build-thesis-example.ps1), and [references/shtthesis-user-guide.txt](references/shtthesis-user-guide.txt) as needed.

## Workflow

1. Determine the task mode:
   - create a new thesis skeleton
   - lint an existing Word or LaTeX thesis
   - fix concrete formatting violations
   - migrate existing content into a compliant thesis structure
2. Apply precedence in this order:
   - school rules
   - bundled reference
   - `shtthesis` defaults only when they do not conflict
3. Read only the relevant reference sections:
   - content and required sections: `## 3` and `## 4`
   - citation rules: `## 5` and `### 7.8`
   - page layout and typography: `## 6`
   - LaTeX template behavior: `## 7`
   - implementation checklist: `## 8`
   - starter project skeleton: `references/thesis-starter.tex`
   - example dual-build wrapper: `references/build-thesis-example.ps1`
   - raw shtthesis guide text: `references/shtthesis-user-guide.txt`
4. Produce concrete outputs:
   - file edits or code
   - rule-based findings with exact file references
   - missing items and the required fixes
   - build commands and assumptions

## LaTeX Defaults

Prefer `shtthesis` for ShanghaiTech graduate theses.

Use these defaults unless the existing project already has a justified alternative:

- `\documentclass[master]{shtthesis}` or `\documentclass[doctor]{shtthesis}`
- compile with `latexmk -pdfxe`
- use `latexmk -pdflua` if cross-platform PDF compatibility becomes a problem
- do not use `pdfLaTeX`
- keep `reference.bib` and `shanghaitech-emblem.pdf` in the project root
- set thesis metadata only through `\shtsetup{...}`
- use the standard structure:

```latex
\maketitle
\frontmatter
\begin{abstract}...\end{abstract}
\begin{abstract*}...\end{abstract*}
\makeindices
\mainmatter
% chapters
\makebiblio
\appendix
% appendices
\backmatter
% acknowledgement / resume / publications
```

- use `anonymous` for blind-review output
- use `print` for print-ready output
- do not enable `comfort` by default for graduate theses
- if strict bilingual figure/table captions are required, load `bicaption` with `list=off`

Use this minimal metadata pattern when creating a new project:

```latex
\shtsetup{
  degree-name = {...},
  degree-name* = {...},
  title = {...},
  title* = {...},
  keywords = {...},
  keywords* = {...},
  author = {...},
  author* = {...},
  institution = {...},
  institution* = {...},
  supervisor = {...},
  supervisor* = {...},
  supervisor-institution = {...},
  discipline-level-1 = {...},
  discipline-level-1* = {...},
  date = {...},
  date* = {...},
  bib-resource = {reference.bib},
}
```

## Linting Checklist

When checking an existing thesis, verify at minimum:

- required sections exist and appear in the correct order
- Chinese and English cover metadata are consistent
- abstracts are both present and semantically aligned
- front matter pagination and right-page starts are correct
- heading depth and numbering follow the school rules
- figure, table, and equation numbering is chapter-based
- reference style and citation commands match the required scheme
- appendix and backmatter ordering is correct
- anonymous and formal builds do not leak author information

If the project already contains build wrappers or automation, preserve them unless they clearly violate the rules.

## Reporting

When the user asks for a review or formatting check:

- report violations before summaries
- cite exact file paths and line references when possible
- distinguish between hard rule violations and template-specific recommendations
- prefer minimal fixes that preserve the author’s writing and project structure

## Related Resources

Read [references/shanghaitech-thesis-format.md](references/shanghaitech-thesis-format.md) when exact wording, page layout values, citation details, or `shtthesis` command behavior is needed.