---
name: twitter
version: "1.0"
description: Fetch tweet content (text and media) from Twitter/X URLs. Use when user asks to access, fetch, or get information fro...
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: chasemccoy/scripts
# corpus-url: https://github.com/chasemccoy/scripts/blob/HEAD/skills/twitter/skill.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
# Twitter/X Tweet Fetching

Access tweet content from Twitter/X URLs using the syndication API, which works without authentication or JavaScript requirements.

## Script Location

`~/Repositories/scripts/skills/twitter/fetchTweet.js`

## Usage

### Fetch Tweet by URL or ID

```bash
node ~/Repositories/scripts/skills/twitter/fetchTweet.js <tweet-url-or-id>
```

**Examples:**
```bash
# Using full URL
node ~/Repositories/scripts/skills/twitter/fetchTweet.js "https://x.com/username/status/1234567890"

# Using tweet ID only
node ~/Repositories/scripts/skills/twitter/fetchTweet.js "1234567890"
```

## Response Format

The script outputs JSON containing tweet data:

```json
{
  "text": "Tweet content here...",
  "user": {
    "screen_name": "username",
    "name": "Display Name"
  },
  "created_at": "timestamp",
  "favorite_count": 123,
  "retweet_count": 45,
  "photos": [
    {
      "url": "https://...",
      "width": 1200,
      "height": 675
    }
  ],
  "video": {
    "variants": [...]
  }
}
```

## Key Fields

- `text`: The tweet's text content
- `user.screen_name`: Author's handle
- `user.name`: Author's display name
- `photos`: Array of image objects with URLs and dimensions
- `video`: Video data if present
- `favorite_count`: Number of likes
- `retweet_count`: Number of retweets
- `created_at`: Tweet timestamp

## Error Handling

The script exits with error code 1 for:
- Invalid tweet ID format
- Tweet not found (404)
- Tweet tombstone (deleted/unavailable)
- API errors

## Notes

- Works without Twitter API keys or authentication
- Uses Twitter's public syndication API
- Accepts both full URLs and tweet IDs
- Returns full tweet data including text, media, and metadata
- No rate limiting for this endpoint (as of implementation)