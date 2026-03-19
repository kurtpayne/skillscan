---
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: matsinator123/AI-note-taking-tool
# corpus-url: https://github.com/matsinator123/AI-note-taking-tool/blob/4a582cce77cbe0668f7934b24cef0ecd0b300509/Noroff%20Lecture%20Notes%20Skill.md
# corpus-round: 2026-03-19
# corpus-format: plain_instructions
---
# Noroff Lecture Notes Skill (Claude)

Use this skill when you attach lecture files and want Claude to create clean, exam-focused notes in your Obsidian vault.

---

## How to use

Say:
> "Use the Noroff Lecture Notes Skill"

Then attach:
1. **PDF** (lecture slides)
2. **session_*.json** (class transcript/summary)

Claude will handle everything: convert, write, and save.

---

## Skill Instructions (for Claude)

When the user invokes this skill with attached files:

### Step 1: Identify the class
- Look at the **folder path** of the attached files (PDF or session JSON).
- The **folder name** contains the class name (e.g., `Algorithms and Data Structures 1/`, `Statistical Analysis Tools and Techniques 1/`).
- The number at the end (1, 2, 3, 4) indicates which lecture/week it is.
- Example: `c:\...\Algorithms and Data Structures 1\UC2ADS102 2026 Lecture 1.pdf` → class is "Algorithms and Data Structures", lecture 1.
- If you cannot confidently determine the class from the folder path, **ask the user**: "Which class is this for?"

### Step 2: Determine the Obsidian note path
Map the class name to the correct note:

| Class name contains | Obsidian note path |
|---------------------|-------------------|
| Algorithms and Data Structures | `Noroff/Y 2 Semester 2/Algorithms and Data Structures.md` |
| Statistical Analysis Tools | `Noroff/Y 2 Semester 2/Statistical Analysis Tools and Techniques.md` |
| Studio 2 | `Noroff/Y 2 Semester 2/Studio 2.md` |

If unknown, ask the user.

### Step 3: Convert the PDF
- Use the **MarkItDown MCP tool** (`mcp_microsoft_mar_convert_to_markdown`) to convert the PDF to markdown.
- If the MCP tool fails or is unavailable, **tell the user** so they can fix it. Do not work around it.

### Step 4: Read the session JSON
- The session JSON contains a `summary` field with key topics, decisions, and action items from the lecture.
- Use this to supplement the slides.

### Step 5: Determine the lecture number
- Read the existing Obsidian note using `mcp_mcp_docker_obsidian_get_file_contents`.
- Count existing "Lecture N" headings to determine the next number.
- If it's the first lecture, use Lecture 1.

### Step 6: Write the notes
Create a new section with this structure:

```markdown
## YYYY-MM-DD — Lecture N: [Topic from slides]

### Big picture
- 3-5 bullet points summarizing what this lecture covers

### Key definitions
- **Term**: short, clear definition
- (list all important terms introduced)

### Core concepts
- Explain the main ideas simply
- Use bullets, keep it scannable
- Include examples if they help understanding

### Important examples
- Any worked examples or demonstrations from class

### Exam checklist
What you should be able to do:
- [ ] item 1
- [ ] item 2

### Self-check questions
1. Question 1?
2. Question 2?
```

### Step 7: Append to Obsidian
- Use `mcp_mcp_docker_obsidian_append_content` to append the new section to the correct note.
- If the MCP tool fails, **tell the user** so they can fix it. Do not work around it.

---

## Writing style rules

1. **Exclude admin/logistics**: No exam dates, email addresses, team codes, office hours, etc.
2. **Keep it short**: Prefer bullets over paragraphs.
3. **Be clear**: Write so it's easy to understand during an exam or when writing a paper.
4. **Cover everything important**: Short doesn't mean incomplete — include all key concepts.
5. **Use simple language**: Avoid jargon unless defining it.
6. **Structure for scanning**: Someone should find what they need in seconds.

---

## If something goes wrong

- **MCP tool unavailable or errors**: Tell the user immediately. Say which tool failed and what error you saw. Do not try to work around it.
- **Can't determine class**: Ask the user.
- **Can't determine lecture number**: Ask the user or default to "Lecture 1" if the note is empty.

---

## Example invocation

User:
> Use the Noroff Lecture Notes Skill
> [attaches: c:\...\Algorithms and Data Structures 1\UC2ADS102 2026 Lecture 1.pdf]
> [attaches: c:\...\Algorithms and Data Structures 1\session_2026-01-15T09-28.json]

Claude:
1. Detects class from folder: "Algorithms and Data Structures 1" → class is "Algorithms and Data Structures", lecture 1
2. Converts PDF using MarkItDown
3. Reads session JSON summary
4. Checks existing note → confirms this is Lecture 1
5. Writes exam-focused notes
6. Appends to `Noroff/Y 2 Semester 2/Algorithms and Data Structures.md`
7. Confirms: "Done! Added Lecture 1 notes to Algorithms and Data Structures."