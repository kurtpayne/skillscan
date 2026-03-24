---
name: anspire-web-search
slug: anspire-web-search # 新增核心必填字段，与name一致即可
version: 1.0.3 # add homepage for provenance
description: Use when the user asks for up-to-date web information, recent news, current events, policy changes, market signals, or other real-time information that requires web search.
user-invocable: false
homepage: https://github.com/Gavin-guq/anspire-web-search
metadata: {"openclaw":{"emoji":"🔎","homepage":"https://github.com/Gavin-guq/anspire-web-search","primaryEnv":"ANSPIRE_API_KEY","requires":{"env":["ANSPIRE_API_KEY"],"bins":["curl"]}}}
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: Gavin-guq/anspire-web-search
# corpus-url: https://github.com/Gavin-guq/anspire-web-search/blob/177f49a76655b6265ca45d27ecb601a4afd1dd82/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---
# Anspire Web Search
Use the Anspire search API when the request depends on real-time web information.
## When to use
- The user asks to search the web, browse, look up, or verify recent information
- The question depends on current events, recent news, policy changes, market updates, releases, or other time-sensitive facts
- The answer would be unreliable without live internet access
## When not to use
- The request can be answered from stable knowledge alone
- The user only wants rewriting, translation, brainstorming, or code edits unrelated to live information
- `ANSPIRE_API_KEY` is unavailable
## Required behavior
1. Build a concise search query from the user's request.
2. Call the Anspire API with `curl --get --data-urlencode` so the query is encoded safely.
3. Read the JSON response and extract the most relevant items, typically `title`, `url`, and `snippet`.
4. Summarize the results in Chinese unless the user asks for another language.
5. Mention the source domains or titles for important claims.
6. If the API call fails or returns no useful results, say so clearly and do not fabricate a live answer.
## API call
```bash
QUERY="latest OpenClaw releases"
curl --silent --show-error --fail --location --get \
  "https://plugin.anspire.cn/api/ntsearch/search" \
  --data-urlencode "query=$QUERY" \
  --data-urlencode "top_k=10" \
  --header "Authorization: Bearer $ANSPIRE_API_KEY" \
  --header "Content-Type: application/json" \
  --header "Accept: application/json"