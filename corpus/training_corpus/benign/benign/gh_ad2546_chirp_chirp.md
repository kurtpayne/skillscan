---
name: chirp
description: "X/Twitter marketing automation for ContextQA. GET tweets using X API v2. POST tweets/replies using browser automation."
homepage: https://github.com/zizi-cat/chirp
metadata: {"clawdhub":{"emoji":"🐦"}}
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: ad2546/chirp
# corpus-url: https://github.com/ad2546/chirp/blob/c57f6d761032c0633d296a248b4fce6a812c6499/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# chirp

X/Twitter marketing automation for ContextQA using a **hybrid approach**:

- **GET operations** (search, read timelines) → X API v2
- **POST operations** (tweets, replies) → Browser automation

This gives us fast, reliable reads via API while maintaining human-like posting through the browser.

## Prerequisites

### For API Reads
- X Developer API credentials in environment:
  - `CONSUMER_KEY`, `CONSUMER_SECRET`
  - `ACCESS_TOKEN`, `ACCESS_TOKEN_SECRET`
- Python 3 with `requests_oauthlib`

### For Browser Posts
- OpenClaw browser configured with `profile: openclaw, headless: true`
- X/Twitter account cookies saved (one-time setup)

### One-time Browser Setup
```bash
# Start browser
browser action=start profile=openclaw

# Open Twitter (login if needed, cookies persist)
browser action=open profile=openclaw targetUrl="https://x.com/home"
```

---

## GET Operations (X API v2)

### Search Tweets

```bash
# Search for QA pain points
python3 ~/.x_api/x_api_poster.py search "flaky tests CI/CD"
python3 ~/.x_api/x_api_poster.py search "test maintenance nightmare"
python3 ~/.x_api/x_api_poster.py search "selenium brittle scripts"
python3 ~/.x_api/x_api_poster.py search "QA automation broken"

# Get JSON output for processing
python3 ~/.x_api/x_api_poster.py search "flaky tests" | jq '.data[] | {id: .id, text: .text, metrics: .public_metrics}'
```

### Get User Tweets

```bash
# Get recent tweets from a user
python3 ~/.x_api/x_api_poster.py tweets <user_id>

# Get your own tweets
python3 ~/.x_api/x_api_poster.py tweets
```

---

## POST Operations (Browser Automation)

### Critical: Working Reply Workflow (Verified)

**⚠️ KEY LESSONS LEARNED:**
1. **Use 5+ second delays** between actions (not 2-3s)
2. **Verify text is entered** before clicking Reply
3. **Reply button is disabled until text exists**
4. **Take screenshots at each step** for debugging

### Post a Reply (Step-by-Step)

```bash
# Step 1: Navigate to target tweet
browser action=open profile=openclaw targetUrl="https://x.com/<username>/status/<tweet_id>"

# Step 2: Wait for page load (CRITICAL - 5 seconds)
exec command="sleep 5"

# Step 3: Take screenshot to verify page loaded
browser action=screenshot profile=openclaw

# Step 4: Get snapshot to find Reply button ref
browser action=snapshot profile=openclaw refs=aria compact=true

# Step 5: Click Reply button
browser action=act profile=openclaw request={"kind":"click","ref":"<reply-button-ref>"}

# Step 6: Wait for dialog (CRITICAL - 4 seconds)
exec command="sleep 4"

# Step 7: Get snapshot of dialog
browser action=snapshot profile=openclaw refs=aria compact=true

# Step 8: Type reply text
browser action=act profile=openclaw request={"kind":"type","ref":"<textbox-ref>","text":"<your-reply>"}

# Step 9: Wait for text entry (CRITICAL - 3 seconds)
exec command="sleep 3"

# Step 10: Verify text entered via screenshot
browser action=screenshot profile=openclaw

# Step 11: Get fresh snapshot (Reply button enables after text)
browser action=snapshot profile=openclaw refs=aria compact=true

# Step 12: Click Reply button (now enabled)
browser action=act profile=openclaw request={"kind":"click","ref":"<reply-button-ref>"}

# Step 13: Wait for submission (CRITICAL - 5 seconds)
exec command="sleep 5"

# Step 14: Verify success via screenshot
browser action=screenshot profile=openclaw

# Step 15: Optional - verify via API
python3 ~/.x_api/x_api_poster.py tweets | jq '.data[0]'
```

### Post a Reply with GIF (For Frustration/Funny Replies)

**For replies expressing shared frustration or humor, add a GIF** - makes ContextQA feel more relatable and human.

```bash
# Steps 1-7: Same as basic reply workflow above

# Step 8: Type reply text
browser action=act profile=openclaw request={"kind":"type","ref":"<textbox-ref>","text":"<your-reply>"}
exec command="sleep 3"

# Step 9: Click "Add a GIF" button
browser action=act profile=openclaw request={"kind":"click","ref":"<add-gif-button-ref>"}
exec command="sleep 5"

# Step 10: Get snapshot of GIF picker
browser action=snapshot profile=openclaw refs=aria compact=true

# Step 11: Search for relevant GIF
browser action=act profile=openclaw request={"kind":"type","ref":"<gif-search-ref>","text":"<search-term>"}
exec command="sleep 5"

# Step 12: Get snapshot with results and pick a GIF
browser action=snapshot profile=openclaw refs=aria compact=true
browser action=act profile=openclaw request={"kind":"click","ref":"<gif-result-ref>"}
exec command="sleep 3"

# Step 13: Get fresh snapshot (Reply button now enabled)
browser action=snapshot profile=openclaw refs=aria compact=true

# Step 14: Click Reply button (now enabled)
browser action=act profile=openclaw request={"kind":"click","ref":"<reply-button-ref>"}
exec command="sleep 5"

# Step 15: Verify success
browser action=screenshot profile=openclaw
```

**When to use GIFs in replies:**
- **Shared frustration:** "Ugh, flaky tests are the worst 😤" + facepalm GIF
- **Celebrating wins:** "That's awesome! 🎉" + celebration GIF
- **Relatable moments:** "Me debugging at 3am" + tired/exhausted GIF
- **Humor:** Lighthearted exchanges where a GIF adds personality

**Avoid GIFs for:**
- Serious technical deep-dives
- Direct product pitches (Tier 3)
- First-time cold replies (keep it professional)

### Post a Tweet (Step-by-Step)

```bash
# Navigate to home
browser action=open profile=openclaw targetUrl="https://x.com/home"
exec command="sleep 5"

# Get snapshot
browser action=snapshot profile=openclaw refs=aria compact=true

# Click compose (look for "Post text" textbox)
browser action=act profile=openclaw request={"kind":"click","ref":"<compose-textbox-ref>"}
exec command="sleep 3"

# Get snapshot
browser action=snapshot profile=openclaw refs=aria compact=true

# Type content with human-like timing
browser action=act profile=openclaw request={"kind":"type","ref":"<compose-textbox-ref>","text":"<tweet-content>"}
exec command="sleep 3"

# Verify text entered
browser action=screenshot profile=openclaw

# Get fresh snapshot (Post button enables after text)
browser action=snapshot profile=openclaw refs=aria compact=true

# Click Post
browser action=act profile=openclaw request={"kind":"click","ref":"<post-button-ref>"}
exec command="sleep 5"

# Verify success
browser action=screenshot profile=openclaw
```

### Post a Tweet with GIF (Frustration/Funny Content)

**For relatable/frustration content, ALWAYS add a GIF** - makes the brand more human and engaging.

```bash
# Navigate to home
browser action=open profile=openclaw targetUrl="https://x.com/home"
exec command="sleep 5"

# Get snapshot to find compose box
browser action=snapshot profile=openclaw refs=aria compact=true

# Click compose textbox
browser action=act profile=openclaw request={"kind":"click","ref":"<compose-textbox-ref>"}
exec command="sleep 3"

# Type tweet content
browser action=act profile=openclaw request={"kind":"type","ref":"<compose-textbox-ref>","text":"<tweet-content>"}
exec command="sleep 3"

# Click "Add a GIF" button
browser action=act profile=openclaw request={"kind":"click","ref":"<add-gif-button-ref>"}
exec command="sleep 5"

# Get snapshot of GIF picker
browser action=snapshot profile=openclaw refs=aria compact=true

# Search for relevant GIF (e.g., "frustrated computer", "facepalm", "celebration")
browser action=act profile=openclaw request={"kind":"type","ref":"<gif-search-ref>","text":"<search-term>"}
exec command="sleep 5"

# Get snapshot with search results
browser action=snapshot profile=openclaw refs=aria compact=true

# Click on a GIF that matches the vibe
browser action=act profile=openclaw request={"kind":"click","ref":"<gif-result-ref>"}
exec command="sleep 3"

# Get fresh snapshot (Post button now enabled)
browser action=snapshot profile=openclaw refs=aria compact=true

# Click Post
browser action=act profile=openclaw request={"kind":"click","ref":"<post-button-ref>"}
exec command="sleep 5"

# Verify success
browser action=screenshot profile=openclaw
```

**GIF Search Keywords by Content Type:**
- **Frustration/CI failures:** "frustrated computer", "facepalm", "rage", "smashing keyboard"
- **Celebration/wins:** "celebration", "success", "win", "happy dance"
- **Confusion/bugs:** "confused", "wtf", "mind blown", "thinking"
- **Relatable moments:** "tired", "exhausted", "coffee", "dead inside"
- **Testing/QA specific:** "testing", "qa", "bug", "fixing bugs"

**Example:**
```bash
# Tweet about CI failures with frustrated GIF
browser action=act profile=openclaw request={"kind":"type","ref":"e169","text":"POV: Your test suite passed locally but failed in CI.\n\nWe've all been there."}
browser action=act profile=openclaw request={"kind":"click","ref":"e274"}  # Add GIF button
# Search: "frustrated computer"
# Pick: "Disappointed Computer Anger GIF"
```

---

## ContextQA Marketing Workflows

### 1. Find Targets via API

```bash
# Search for QA pain points
QUERIES=(
  "flaky tests CI/CD"
  "test maintenance nightmare"
  "selenium brittle scripts"
  "QA automation broken"
  "regression testing takes forever"
  "end to end testing pain"
)

# Run search and save results
python3 ~/.x_api/x_api_poster.py search "flaky tests" > /tmp/targets.json

# Parse for high-engagement tweets
cat /tmp/targets.json | jq '.data[] | select(.public_metrics.like_count > 10) | {id: .id, text: .text[0:80], likes: .public_metrics.like_count}'
```

**Filter criteria:**
- 10+ likes = worth engaging
- 100+ likes = high visibility
- Skip bot accounts, crypto, job posts

### 2. Reply Strategy (3-Tier System)

**Tier 1: Pure Value (70%)** - No product mention
```bash
# Example pure value replies:
"60% of QA time is test maintenance. The real cost isn't writing tests—it's keeping them alive when the UI changes."
"Flaky tests are worse than no tests. They train teams to ignore CI/CD failures. What's your flake detection strategy?"
```

**Tier 2: Soft Mention (20%)** - Subtle ContextQA reference
```bash
"Agreed — we cut maintenance by 80% moving to context-aware AI testing. Same test logic, but the AI adapts when the UI changes underneath it."
"Self-healing tests cut our maintenance by 80%. The tech exists now—just not in the legacy tools most teams use."
```

**Tier 3: Direct Pitch (10%)** - Only when asked for recommendations
```bash
"ContextQA's AI Auto Heal handles exactly this—adapts to UI changes automatically. Worth checking out."
```

### 3. Full Engagement Workflow

**Step 1: Find Targets via API**
```bash
python3 ~/.x_api/x_api_poster.py search "flaky tests" > /tmp/search_results.json
# Extract tweet ID from results
cat /tmp/search_results.json | jq -r '.data[0].id'
```

**Step 2: Analyze via API**
- Check `public_metrics` (likes, retweets)
- Verify QA/testing relevance from text
- Check if already engaged (local log)

**Step 3: Choose Reply Style**
```javascript
const styles = ['expert', 'peer', 'curious', 'contrarian'];
// Expert: Data points, numbers
// Peer: "Been there", shared experience
// Curious: Follow-up questions
// Contrarian: Respectful pushback
```

**Step 4: Post Reply via Browser**
```bash
# Open tweet
browser action=open profile=openclaw targetUrl="https://x.com/i/status/<tweet_id>"
exec command="sleep 5"
browser action=snapshot profile=openclaw
browser action=snapshot profile=openclaw refs=aria compact=true

# Click reply
browser action=act profile=openclaw request={"kind":"click","ref":"<reply-button-ref>"}
exec command="sleep 4"
browser action=snapshot profile=openclaw refs=aria compact=true

# Type reply (under 280 chars, no hashtags)
browser action=act profile=openclaw request={"kind":"type","ref":"<textbox-ref>","text":"<reply>"}
exec command="sleep 3"
browser action=screenshot profile=openclaw

# Get fresh snapshot (Reply button enables after text)
browser action=snapshot profile=openclaw refs=aria compact=true

# Click Reply (now enabled)
browser action=act profile=openclaw request={"kind":"click","ref":"<reply-button-ref>"}
exec command="sleep 5"

# Verify success
browser action=screenshot profile=openclaw
```

**Step 5: Log Engagement**
```bash
# Track to avoid duplicates
echo '{"tweetId":"...","author":"...","engagedAt":"2026-02-03T20:00:00Z","tier":"pure_value"}' >> ~/.x_api/engagement_log.jsonl
```

### 4. Original Content Posting (Browser)

```bash
# Navigate to home
browser action=open profile=openclaw targetUrl="https://x.com/home"
exec command="sleep 5"
browser action=snapshot profile=openclaw refs=aria compact=true

# Click compose
browser action=act profile=openclaw request={"kind":"click","ref":"<compose-textbox-ref>"}
exec command="sleep 3"
browser action=snapshot profile=openclaw refs=aria compact=true

# Type content
browser action=act profile=openclaw request={"kind":"type","ref":"<compose-textbox-ref>","text":"Gartner predicts agentic AI will handle 40% of QA workloads by 2026. The shift is happening now."}
exec command="sleep 3"
browser action=screenshot profile=openclaw

# Get fresh snapshot (Post button enables after text)
browser action=snapshot profile=openclaw refs=aria compact=true

# Click Post
browser action=act profile=openclaw request={"kind":"click","ref":"<post-button-ref>"}
exec command="sleep 5"
browser action=screenshot profile=openclaw
```

**Content Types to Rotate:**
- **Data insight (25%):** "Gartner predicts agentic AI will handle 40% of QA workloads by 2026." *(text only)*
- **Relatable (30%):** "POV: Your test suite passed locally but failed in CI. We've all been there." *(+ GIF for frustration/humor)*
- **Community question (15%):** "What's your flake rate? Be honest. Industry average is 10-20%." *(+ GIF if playful tone)*

**GIF Strategy by Content Type:**
- **Frustration/Relatable posts:** ALWAYS add GIF - "frustrated computer", "facepalm", "rage"
- **Celebration/Wins:** Add GIF - "celebration", "success", "win"
- **Data/Technical posts:** No GIF - keep it clean and professional
- **Questions:** Optional GIF for playful tone - "thinking", "curious", "shrug"

---

## Delay Guidelines (CRITICAL)

### Minimum Delays (Verified Working)
```bash
# After page load
exec command="sleep 5"

# After clicking Reply (dialog open)
exec command="sleep 4"

# After typing text (before clicking submit)
exec command="sleep 3"

# After clicking Reply/Post (submission)
exec command="sleep 5"

# Between multiple engagements
exec command="sleep 30"  # 30+ seconds to avoid rate limits
```

### Why Longer Delays Matter
- X's UI is JavaScript-heavy and loads asynchronously
- Reply button is **disabled until text exists**
- Button refs change after state updates
- Rapid actions trigger rate limiting

---

## Safety Limits

- Max 3 replies per session
- 7-day cooldown per author
- Skip authors <1K or >500K followers (unless viral)
- Skip bot accounts, crypto, job posts
- No replies to same tweet twice
- No identical reply text in same session
- **Wait 30+ seconds between replies** to avoid rate limits

---

## Rate Limits

| Operation | Method | Limit | Window |
|-----------|--------|-------|--------|
| Search tweets | API | 450 | 15 min |
| Get user tweets | API | 1500 | 15 min |
| Post tweets | Browser | ~50 | 24 hours |
| Post replies | Browser | ~50 | 24 hours |

---

## Python API Client Reference

Full client at `~/.x_api/x_api_poster.py`:

```python
#!/usr/bin/env python3
import os
import json
from requests_oauthlib import OAuth1Session

CONSUMER_KEY = os.environ.get("CONSUMER_KEY")
CONSUMER_SECRET = os.environ.get("CONSUMER_SECRET")
ACCESS_TOKEN = os.environ.get("ACCESS_TOKEN")
ACCESS_TOKEN_SECRET = os.environ.get("ACCESS_TOKEN_SECRET")

def get_oauth_session():
    return OAuth1Session(
        CONSUMER_KEY, client_secret=CONSUMER_SECRET,
        resource_owner_key=ACCESS_TOKEN,
        resource_owner_secret=ACCESS_TOKEN_SECRET
    )

def search_tweets(query, max_results=10):
    """Search recent tweets - returns JSON with id, text, public_metrics"""
    oauth = get_oauth_session()
    url = "https://api.twitter.com/2/tweets/search/recent"
    params = {
        "query": query,
        "max_results": max_results,
        "tweet.fields": "author_id,created_at,public_metrics,conversation_id"
    }
    response = oauth.get(url, params=params)
    return response.json() if response.status_code == 200 else None

def get_user_tweets(user_id="2282952512", max_results=10):
    """Get tweets from a user"""
    oauth = get_oauth_session()
    url = f"https://api.twitter.com/2/users/{user_id}/tweets"
    params = {"max_results": max_results, "tweet.fields": "created_at,public_metrics"}
    response = oauth.get(url, params=params)
    return response.json() if response.status_code == 200 else None
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| API 401 | Check env vars: `echo $CONSUMER_KEY` |
| API 403 | Need Elevated access for search |
| Reply button disabled | **Text not entered yet** - verify via screenshot |
| Click "succeeds" but no post | **Increase delays** - use 5s, not 2s |
| Rate limited | Wait 30+ min, reduce frequency |
| Stale refs | Always get fresh snapshot before acting |
| Dialog not opening | Wait 4+ seconds after clicking Reply |

### Debug Checklist
- [ ] Screenshot after page load
- [ ] Screenshot after clicking Reply
- [ ] Screenshot after typing text
- [ ] Screenshot after clicking submit
- [ ] Verify via API: `python3 ~/.x_api/x_api_poster.py tweets`

---

## Quick Reference

| Task | Command |
|------|---------|
| Search tweets | `python3 ~/.x_api/x_api_poster.py search "query"` |
| Get user tweets | `python3 ~/.x_api/x_api_poster.py tweets [user_id]` |
| Post tweet | Browser workflow with 5s delays |
| Reply to tweet | Browser workflow with 5s delays |

---

## Memory: What Worked (2026-02-03)

**Successful reply posted to @vijaya92859:**
- Used 5-second delays between all actions
- Took screenshots at each step for verification
- Reply button is disabled until text is entered
- Required fresh snapshot after typing to get enabled button ref
- Verified success via screenshot showing reply live

**Working delay pattern:**
1. Page load: 5s
2. Click Reply: 4s
3. Type text: 3s  
4. Click submit: 5s
5. Between multiple replies: 30s+

---

**TL;DR**: Use API for reads (fast). Use browser for posts with **5+ second delays** and **screenshot verification at each step**. 🐦