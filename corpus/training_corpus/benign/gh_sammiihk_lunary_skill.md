---
name: dev
version: "1.0"
description: Start the Next.js development server
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: Sammii-HK/lunary
# corpus-url: https://github.com/Sammii-HK/lunary/blob/HEAD/.claude/skills/dev/SKILL.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
# Development Server

Start the Next.js development server with Turbopack.

## Steps

1. **Check for existing server** on port 3000:

   ```bash
   lsof -i :3000
   ```

2. **If port is in use**, ask user if they want to kill it

3. **Start dev server**:
   ```bash
   pnpm dev
   ```

The server runs at http://localhost:3000

## Notes

- Uses Turbopack for faster hot reloading
- Run in background if user wants to continue working
- Ctrl+C or `pkill -f "next dev"` to stop