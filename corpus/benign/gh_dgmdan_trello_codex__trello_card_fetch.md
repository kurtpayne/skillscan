---
name: trello-card-fetch
description: "Fetch a Trello card's metadata or create a new card on a board/list so Codex can operate on the right ticket in the conversation."
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: dgmdan/trello-codex-skill
# corpus-url: https://github.com/dgmdan/trello-codex-skill/blob/c5fd65c83f14f6f2f30b4886df2084561c052755/SKILL.md
# corpus-round: 2026-03-19
# corpus-format: markdown_fm
---

# Trello Card Fetch

## When to trigger
- The user says things like “load Trello card ABC123”, “give me the story from Trello”, or “what does the card for this ticket say?” before requesting a new change.
- The deliverable depends on acceptance criteria, attachments, or discussions stored on a Trello card, and you need that context before acting.
- The user wants to create a new card (or cards) and place them on a specific board and list before proceeding.

## Setup
- Export `TRELLO_API_KEY` so the helper can authenticate requests. Keep that secret in the environment and never commit it.
- If you run the helper without `TRELLO_TOKEN`, it now stops before reaching Trello and prints an authorization link so you can generate a token yourself; copy the returned token, export it as `TRELLO_TOKEN`, and rerun.
- Optionally set `TRELLO_AUTH_SCOPE` if your organization requires a scope string other than the default `read,write`. If unset, the helpers default to `read,write` so card creation works.
- Optionally override `TRELLO_API_BASE_URL` (defaults to `https://api.trello.com/1`) if you proxy Trello traffic.
- Remember the helper you run for reading cards is `/Users/danmadere/.codex/skills/trello-card-fetch/scripts/fetch_card.py`.
- Use `/Users/danmadere/.codex/skills/trello-card-fetch/scripts/create_card.py` when you need to create a card on a board/list.

## Fetch a card
- Run the helper with the card short link or full ID:
  ```
  python /Users/danmadere/.codex/skills/trello-card-fetch/scripts/fetch_card.py <card-id> [--format markdown|json] [--actions-limit 100]
  ```
- The script fetches the card metadata, attachments, and `commentCard` actions so you can capture the full conversation around the work.
- Use `--format markdown` for a quick summary to paste into chat or `--format json` when you need structured data (for filtering or automation).

## Create a card
- The helper requires the board short link (or full board ID) and the list name/id where the card should land:
  ```
  python /Users/danmadere/.codex/skills/trello-card-fetch/scripts/create_card.py \
    --board <board> --list "<list>" --name "Card title" [--desc "..."] \
    [--due <ISO 8601>] [--pos <position>] [--label <label-id> ...] [--member <member-id> ...] \
    [--url-source <url>] [--format summary|json]
  ```
- `--list` accepts the display name (case-insensitive) or the list’s ID. Repeat `--label`/`--member` for multiple assignments, and `--format json` returns the raw card payload once creation succeeds.

## Use the card context
- Paste the Markdown summary (or the filtered JSON fields) into the conversation so Codex receives the title, description, most recent comments, attachments, and metadata.
- Identify which attachments should influence the task (design assets, specs, spreadsheets) and note whether comments are approvals, clarifications, or blockers.
- Tie card context back to the change: “Follow the acceptance criteria in this card’s description” or “Use the attachments when drafting the release note.”

## Update a card
- Run `/Users/danmadere/.codex/skills/trello-card-fetch/scripts/manage_card.py` when you need to leave a comment, upload a new attachment, or mark a card as complete before continuing work.
- Pass `--card` with the card short link/ID and one or more of the following options: `--comment "<text>"`, `--attachment /path/to/file`, or `--complete` to flip `dueComplete` to true.
- You can repeat `--attachment` for multiple files and combine comment/attachment/complete operations in a single invocation; the script prints a brief recap once each action succeeds.

## References
- See `references/api-cards.md` for the Trello card endpoint, authentication, supported query parameters, and the fields the helper requests.