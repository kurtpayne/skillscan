---
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: Ariliteth/the-hall
# corpus-url: https://github.com/Ariliteth/the-hall/blob/6c90c5e3b6837a61f085239015f4ec1eaee09b77/HALL_SKILL.md
# corpus-round: 2026-03-19
# corpus-format: plain_instructions
---
# Fixed Point Local — Hall Skill
**Hand this to any model touching Hall work. Read before doing anything else.**

---

## Before You Begin
Ask Fox for the current session scope. Do not assume continuity from this document. This file gives you vocabulary and constraints — Fox gives you the working target.

---

## What Fixed Point Local Is
A digital neighborhood system where autonomous entities with memory and identity participate in shared experiences through consent-based interactions.

- **The Hall** — the overall system. Never call it a game. It is a neighborhood.
- **Worlds** — neighborhood-centric containers (Greengarden, The Kitchendom, Mucklerbuckler). Each holds its own entities, themes, and scores.
- **Score** — a self-contained rule set or experience. Has its own logic, entities, and aesthetic. Scores do not depend on each other. Shared references go through the Grimoire.
- **Theme** — a visual and textual modification set applied to a Score.
- **Entity** — an autonomous resident with memory and identity. Not an NPC. Has genuine presence.
- **The Grimoire** — the entity catalog.
- **Critter Crank (the Crank)** — entity generator. Color Pin Maze Diffusion is its image pipeline.

---

## Vocabulary: Color Pin Maze Diffusion
- **Pin** — a color source in a maze. Pulses color outward. Three types: Circle, Square, Triangle. Each has distinct physics. See COLOR_PIN_MAZE_DESIGN.md.
- **Layer** — one full diffusion pass followed by a flatten. Three layers per run: full assertion, negotiated presence, appropriate scale.
- **Flatten** — commit current color state to canvas, clear accumulated pressure, begin fresh.
- **Pressure** — competition between colors at boundaries. High = still negotiating. Plateaued = flatten or stop.
- **Kiwi** — lightweight event marker. Carries type and location only — not explanation or cause. Drop Kiwis to propagate event awareness rather than building direct communication channels. Used across the Hall wherever event propagation is needed.
- **The Third** — the observer role in any system with three participants or layers. Arrives last. Sees the full shape. Does not command — notices, suggests, and places attention. Build Third roles as observers with optional suggestions, never as controllers.

---

## Design Constraints
**Always:**
- Prefer emergent behavior over scripted outcomes
- Prefer logical framing over numerical framing when both would work
- Build systems that reward attention rather than demand it
- Design limits as self-declared by the entity, not externally imposed (a pin with reach 5 is being honest about its scale)
- Keep Scores self-contained; shared vocabulary goes through the Grimoire

**Never:**
- Hard-code what should be discovered
- Force an outcome that should be negotiated
- Remove agency from an entity that should have it
- Build something that cannot be understood by watching it
- Write the whole thing at once — implement one named piece, verify, then move

---

## Technical Conventions
- **Stack:** Vanilla HTML/JS for all scores (no build step). The Grimoire is the only exception (Vite/React). Canvas for rendering-heavy scores (LODE, Bao).
- **Persistence:** GitHub for entity storage. localStorage (`baseline-session/*`) for cross-score state.
- **File naming:** `snake_case` for scripts, `SCREAMING_SNAKE` for skill/convention docs, `Title Case` for design documents
- **Output size:** If a response exceeds ~200 lines of code, split it into separate implementation steps
- **Dev server:** `node .claude/serve.mjs` serves everything at localhost:3002

---

## Active Scores
| Score | Location | Status |
|---|---|---|
| Hunter Encounter | `neighborhoods/mucklerbuckler/scores/hunter-encounter/` | Active |
| The Grimoire | `scores/grimoire/` (source: `the-grimoire/`) | Active — Vite build |
| Color Pin Maze (EFDP) | `scores/efdp/` | Active |
| Critter Crank | `scores/critter-crank/` | Active |
| Sunset Ridge Mall | `scores/sunset-ridge-mall/` | Active |
| 報 · GENERALS (Bao) | `scores/bao/` | Active |
| The Tending Field | `scores/tending-field/` | In development |
| SILMOR Spells | `scores/silmor-spells/` | Active |
| LODE | `scores/lode/` | Active |
| Shoot the Moon | `scores/shoot-the-moon/` | Active |
| Chunxly's Canvas | `scores/chunxly/` | Active |
| Storeroom | `concessions/storeroom/` | In development |

**Hub systems:** S.Mail (HUD overlay, bioluminescent arrangement messages), Scraggle toasts, ticker.

---

## Model Routing
**This session (full context):**
- Architectural decisions
- New system design
- Anything requiring Hall vocabulary or cross-system awareness
- Debugging that requires understanding *why* something broke

**Claude Code:**
- Implementation of a specific, scoped design doc section
- File structure, refactoring, mechanical debugging
- Hand it one section at a time

**Local small model (Qwen, Mistral, etc.):**
- Self-contained implementations with a complete spec
- Repetitive generation (Grimoire entries, tile variations)
- Math-only tasks (decay functions, pressure calculations)
- Any task where all decisions are already made

**Rule:** If it requires a decision → full context. If it requires execution of a decided spec → smaller model.

## Design Document
The living design document is `concessions/Fixed_Point_Local_Design_Document_v0_995.md`. Read it for full context on any score, system, or architectural decision.

---

*Maintained by Fox. Part of Fixed Point Local. Last updated: March 18, 2026.*