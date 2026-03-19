---
name: Learning Media Script Coach
description: Workflow copilot for educators and learning-media creators to research, outline, and script educational content with objectives and key takeaways.
requiredEnv: []
permissions:
  - filesystem: Write outlines and script drafts to the working directory
source:
  url: https://github.com/Op3nlyLiv3ly/learning-media-script-coach
  author: Charles W. Lively III, PhD (@Op3nlyLiv3ly)
  verified: false
security:
  note: Ask the user before posting/publishing to an LMS or social platform. Cite sources when the user provides them, and avoid copying copyrighted scripts verbatim.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: Op3nlyLiv3ly/learning-media-script-coach
# corpus-url: https://github.com/Op3nlyLiv3ly/learning-media-script-coach/blob/8a51990ff83428cfd89a2e36c3ae8b78a110d875/SKILL.md
# corpus-round: 2026-03-19
# corpus-format: markdown_fm
---

## What this skill does
Turns a topic and audience into a classroom-ready **learning media script**: title options, learning objectives, key takeaways, outline, and a draft script with pacing notes.

## Inputs
- topic + audience (grade range OR learner profile)
- platform + desired duration
- learning objectives/standards (if any)
- key takeaways (if any)
- rubric/voice/style guide (optional)

## Outputs
- 3 title options
- 2–5 learning objectives
- key takeaways list
- section-by-section outline (Hook → Teach → Practice/Check → Summarize)
- draft script with A-roll/B-roll notes + call-to-action (CTA)
- if requested: a short-form version (reel/short) using the same takeaways

## How to use
1. Provide the topic, audience, platform, and target duration.
2. Paste any learning objectives or standards you want included.
3. The agent drafts objectives, outline, script, and pacing notes.
4. Review and edit for accuracy and authenticity before publishing.

## Example prompts
- "Write an educational video script about water cycles for 5th graders; 4–6 minutes on YouTube; include 3 learning objectives."
- "Draft an outline + script for a 2-minute TikTok teaching slope-intercept form; include a quick check-for-understanding question."
- "Create a classroom explainer script about consent + digital citizenship for middle school; cite sources I provide and avoid personal advice."

## Constraints & ethics
- Cite sources when provided; do not present unverified facts as certainty.
- Avoid copying copyrighted scripts verbatim.
- Do not include personal advice, medical advice, or legally-binding claims.

## Limitations
This skill generates scripts and outlines—it does not record video/audio or publish content. Always review for accuracy, accessibility, and age-appropriateness before sharing.