---
name: hwp-5-reader
description: >
  **HWP File Reader**: Read, parse, and extract text, tables, images, and objects from Korean Hangul
  Word Processor (.hwp) files. Use this skill whenever the user wants to read, open, extract text from,
  analyze, summarize, extract images from, or work with any .hwp file. This includes: reading HWP
  documents to answer questions about their content, extracting text for translation or analysis,
  converting HWP content to other formats, extracting embedded images/pictures, parsing tables with
  structure, or any task that involves accessing the contents of a .hwp file. Trigger whenever the user
  mentions ".hwp", "한글 파일", "HWP", "아래아한글", "한컴", "한글 문서", or references a filename ending
  in .hwp, regardless of what they plan to do with the content afterward. Also trigger when the user
  uploads a file with a .hwp extension. Supports both regular and distribution (배포용) HWP 5.0
  documents, including compressed and AES-128 encrypted distribution documents.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: SJang1/hwp-5.0-reader-claude-skill
# corpus-url: https://github.com/SJang1/hwp-5.0-reader-claude-skill/blob/b989fe7990f71941329f359e40ea8307c3b167ff/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# HWP File Reader Skill

This skill enables reading HWP (Hangul Word Processor) 5.0 files, which are the standard document format
used in South Korea by the 한글 (Hangul/Arae-a Hangul) word processor made by Hancom Inc.

## When to Use

Use this skill whenever you encounter a `.hwp` file that needs to be read. HWP files are binary files
based on the Microsoft OLE Compound File format, so they can't be read with simple text tools — you need
this specialized parser.

## How It Works

HWP 5.0 files use an OLE (Object Linking and Embedding) compound file structure internally, containing
multiple "streams" (like files within a file). The key streams are:

- **FileHeader**: Document signature, version, and flags (compressed, encrypted, distribution)
- **DocInfo**: Document metadata — fonts, styles, character shapes, paragraph shapes, BinData item mappings
- **BodyText/Section0..N**: The actual document content, stored as data records
- **ViewText/Section0..N**: Used instead of BodyText for distribution (배포용) documents
- **BinData/**: Embedded images and binary objects (png, bmp, jpg, wmf, etc.)
- **PrvText**: Plain-text preview of the document
- **PrvImage**: Preview thumbnail image

Text content is stored as UTF-16LE encoded WCHAR arrays within data records, and the streams
may be zlib-compressed. Distribution documents additionally encrypt the body text streams with
AES-128 ECB, using a key derived from a seed embedded in each stream.

## Capabilities

The reader extracts the following content types from HWP files:

- **Text**: Full paragraph text from all sections, with proper Unicode handling
- **Tables**: Structured table extraction with row/column mapping, cell spans, rendered as markdown
- **Images/Pictures**: Embedded image extraction with BinData mapping (identifies exact filenames like BIN0001.png)
- **OLE Objects**: Detection and metadata extraction for embedded OLE objects
- **Equations**: Equation script text extraction (EQN-compatible format)
- **Video Objects**: Detection of embedded local and web video references

## Dependencies

The script requires these Python packages:

- `olefile` — for reading OLE compound files
- `cryptography` — for decrypting distribution (배포용) documents (only needed if the file is a distribution doc)

Install them if not already present:
```bash
pip install olefile cryptography --break-system-packages
```

## Usage

The core script is at `scripts/hwp_reader.py`. Use it in these ways:

### Extract full text (plain text only)
```bash
python3 <skill-path>/scripts/hwp_reader.py /path/to/document.hwp
```

### Extract rich text with tables and object markers
```bash
python3 <skill-path>/scripts/hwp_reader.py /path/to/document.hwp --format rich
```
This outputs JSON with tables rendered as markdown and image references like `[Image: BIN0001.png]`.

### Get document summary (JSON)
```bash
python3 <skill-path>/scripts/hwp_reader.py /path/to/document.hwp --format summary
```

### Get full output as JSON (includes metadata + text)
```bash
python3 <skill-path>/scripts/hwp_reader.py /path/to/document.hwp --format json
```

### Get preview text only
```bash
python3 <skill-path>/scripts/hwp_reader.py /path/to/document.hwp --preview
```

### List OLE streams
```bash
python3 <skill-path>/scripts/hwp_reader.py /path/to/document.hwp --streams
```

### Extract embedded images
```bash
python3 <skill-path>/scripts/hwp_reader.py /path/to/document.hwp --extract-images /output/dir/
```

### Extract all BinData entries (images + other binary objects)
```bash
python3 <skill-path>/scripts/hwp_reader.py /path/to/document.hwp --extract-all /output/dir/
```

### Save output to file
```bash
python3 <skill-path>/scripts/hwp_reader.py /path/to/document.hwp -o output.txt
```

## Using from Python

You can also import the reader directly in your own Python scripts:

```python
import sys
sys.path.insert(0, '<skill-path>/scripts')
from hwp_reader import HWPReader

with HWPReader('/path/to/document.hwp') as reader:
    # Get all text as a single string
    text = reader.get_full_text()

    # Get text as list of paragraphs
    paragraphs = reader.get_text()

    # Get rich text with tables (markdown) and image markers
    rich_text = reader.get_text_with_objects()

    # Get document metadata
    summary = reader.get_summary()

    # Get preview text
    preview = reader.get_preview_text()

    # List all internal streams
    streams = reader.list_streams()

    # Extract all embedded images to a directory
    reader.extract_images('/output/dir/')

    # Extract all BinData entries
    reader.extract_all_bindata('/output/dir/')
```

## Workflow for Reading HWP Files

1. **Install dependencies** if not already available: `pip install olefile cryptography --break-system-packages`
2. **Run the reader** on the target HWP file to extract content
3. **Choose the right format** based on the task:
   - Plain text (`--format text`): For simple text extraction, translation, search
   - Rich format (`--format rich`): For content with tables and image references — best for comprehensive reading
   - Summary (`--format summary`): For quick overview of document metadata
   - JSON (`--format json`): For programmatic access to all metadata and text
4. **Extract images** if needed: Use `--extract-images` or `--extract-all` to save embedded files
5. **Process the extracted content** as needed (summarize, translate, analyze, convert, etc.)

If the user just wants to know what's in the file, use `--format rich` to get the most complete view.
If the user wants to convert to another format, extract the content first, then use the appropriate
skill (docx, pdf, etc.) to create the output.

## Supported File Types

- **HWP 5.0** files (created by 한글 2002 and later versions: 한글 2005, 2007, 2010, 2014, 2018, 2020, 2022)
- **Regular documents** (BodyText streams, optionally compressed)
- **Distribution documents** (배포용 — ViewText streams, AES-128 encrypted + compressed)

## Limitations

- Does not support HWP 3.0 or older formats (these have a completely different binary structure)
- Does not support HWPX files (.hwpx) — these are XML-based and can be read by unzipping them
- Password-protected (encrypted) documents that require user passwords are not supported
- Table cell merging (col_span/row_span) is tracked but merged content maps to the top-left cell only
- Embedded equations are extracted as script text, not rendered visually
- Image layout positioning (x, y coordinates) is not preserved — only the image reference and order