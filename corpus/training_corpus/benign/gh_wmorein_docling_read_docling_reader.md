---
name: docling-reader
description: Intelligent partial document reading for large files. Use when asked to find information in documents, search PDFs, extract content from large files, or when you need to answer questions about documents that may be too large to read entirely. Triggers on "read document", "find in document", "search PDF", "extract from", "docling", or when working with .docling.json files.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: wmorein/docling-reading-skill
# corpus-url: https://github.com/wmorein/docling-reading-skill/blob/d92d8b9b1c9b7c6419ddea2076246026cb073420/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# Partial Document Reading Skill

Read and extract information from documents intelligently, loading only what's needed into context.

## When to Use This Skill

- User asks questions about document content
- User wants to find specific information in a large document
- Working with `.docling.json` sidecar files
- Document is potentially too large to read entirely (~50k+ characters)

## Core Workflow

### Step 1: Analyze the Document

First, determine document size and structure:

```bash
python $SKILL_DIR/scripts/analyze_document.py <document_path>
```

This returns:
- Total size (characters and estimated tokens)
- Whether full read is recommended
- Document structure (sections/headings if available)
- Content type (docling JSON or plain text/markdown)

**Decision Point:**
- If `full_read_recommended: true` → Read the entire document normally
- If `full_read_recommended: false` → Continue to Step 2

### Step 2: Review Document Outline

For large documents, first examine the structure:

```bash
python $SKILL_DIR/scripts/analyze_document.py <document_path> --outline
```

This shows the document's hierarchical structure (headings, sections) without content. Use this to:
- Understand document organization
- Identify sections likely to contain relevant information
- Plan your search strategy

### Step 3: Search for Concepts

Search for relevant terms or concepts:

```bash
python $SKILL_DIR/scripts/search_document.py <document_path> "<search_terms>" [--max-results N]
```

Arguments:
- `search_terms`: Space-separated keywords or a phrase in quotes
- `--max-results`: Limit number of results (default: 10)

Returns matches with:
- Location (section path or line numbers)
- Brief context snippet
- Match relevance score

### Step 4: Read Relevant Sections

Based on search results, read specific sections:

**Option A: Read by section path (for structured documents)**
```bash
python $SKILL_DIR/scripts/read_section.py <document_path> --section "<section_path>"
```

**Option B: Read by line range (for unstructured documents)**
```bash
python $SKILL_DIR/scripts/read_section.py <document_path> --lines <start>-<end>
```

**Option C: Read around a match with context**
```bash
python $SKILL_DIR/scripts/read_section.py <document_path> --around <line_number> --context <paragraphs>
```

The `--context` flag specifies how many paragraphs before/after to include (default: 5).

### Step 5: Expand Context if Needed

If the retrieved content doesn't fully answer the question:

1. **Expand the current section**: Read parent section or adjacent sections
2. **Search for related terms**: Try synonyms or related concepts
3. **Read sequential sections**: Get the next/previous section

```bash
# Read parent section
python $SKILL_DIR/scripts/read_section.py <document_path> --section "<parent_section_path>"

# Read adjacent content
python $SKILL_DIR/scripts/read_section.py <document_path> --lines <start>-<end> --expand <paragraphs>
```

## Document Format Handling

### Docling JSON Files (.docling.json)

These are the preferred format with full structure support:
- Hierarchical sections and headings preserved
- Tables and figures identified
- Accurate section-based navigation

The scripts automatically detect and parse docling format.

### Plain Text/Markdown Fallback

For documents without docling sidecars:
- Structure inferred from markdown headings (`#`, `##`, etc.)
- Paragraph boundaries detected by blank lines
- Line-based navigation available

### Locating Docling Sidecars

When given a document path like `report.pdf`, check for:
1. `report.pdf.docling.json` (same directory)
2. `report.docling.json` (same directory)
3. `.docling/report.json` (docling cache directory)

## Size Thresholds

| Document Size | Recommendation |
|---------------|----------------|
| < 50,000 chars | Read entirely |
| 50k - 200k chars | Use outline + targeted reading |
| > 200,000 chars | Always use search + section reading |

These translate roughly to:
- < 12,500 tokens: Full read OK
- 12.5k - 50k tokens: Selective reading
- > 50k tokens: Must use partial reading

## Best Practices

1. **Start with the outline** for unfamiliar documents
2. **Search broadly first**, then narrow down
3. **Read smallest sufficient section** - don't over-fetch
4. **Cite your sources** - mention which section information came from
5. **Acknowledge limitations** - if information might be in unread sections, say so

## Example Workflows

### Finding a Definition

```
User: "What does this textbook say about photosynthesis?"

1. Analyze document → 150k chars, has structure
2. Get outline → See "Chapter 4: Plant Biology" → "4.2 Photosynthesis"
3. Read section "Chapter 4/4.2 Photosynthesis"
4. Answer with citation: "According to section 4.2..."
```

### Answering a Specific Question

```
User: "Does the contract mention termination clauses?"

1. Analyze document → 80k chars, structured
2. Search for "termination" → 3 matches in sections 8.1, 8.3, 12.2
3. Read those sections
4. Synthesize answer from multiple sections
```

### Exploring an Unfamiliar Document

```
User: "Summarize the key findings in this research paper"

1. Analyze document → 45k chars (borderline)
2. Get outline → See Abstract, Introduction, Methods, Results, Discussion, Conclusion
3. Read Abstract and Conclusion first (likely contains key findings)
4. If needed, read Results section for details
```

## Error Handling

- If document not found: Report error, ask user to verify path
- If docling parsing fails: Fall back to plain text mode
- If search returns no results: Suggest alternative search terms
- If section not found: List available sections