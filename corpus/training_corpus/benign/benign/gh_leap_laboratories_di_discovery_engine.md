---
name: discovery-engine
homepage: https://disco.leap-labs.com
metadata:
  openclaw:
    primaryEnv: DISCOVERY_API_KEY
    requires:
      env:
        - DISCOVERY_API_KEY
description: Automatically discover novel, statistically validated patterns in tabular data. Find insights you'd otherwise miss, far faster and cheaper than doing it yourself (or prompting an agent to do it). Discovery Engine systematically searches for feature interactions, subgroup effects, and conditional relationships you wouldn't think to look for, validates each on hold-out data with FDR-corrected p-values, and checks every finding against academic literature for novelty. Returns structured patterns with conditions, effect sizes, citations, and novelty scores.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: leap-laboratories/discovery-engine
# corpus-url: https://github.com/leap-laboratories/discovery-engine/blob/81fd6fc3a42a9e5f9a0eac0088449b8791c5cb0f/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# Discovery Engine

## Integration Options

- **MCP server** — remote server at `https://disco.leap-labs.com/mcp`, no install required. Best for datasets at a URL.
- **Python SDK** — `pip install discovery-engine-api`. **Use this for local files of any size.** Runs on your machine and streams files directly — no base64, no size limits.

**Quick rule:** if the data is at a URL, use `file_url` in `discovery_upload`. If it's a local file, use the Python SDK — or if Python isn't available, upload directly via the presign API and pass the result to `discovery_analyze`. Don't use `file_content` (base64) unless the file is already in memory and tiny.

---

## MCP Server

Add to your MCP config:

```json
{
  "mcpServers": {
    "discovery-engine": {
      "url": "https://disco.leap-labs.com/mcp",
      "env": { "DISCOVERY_API_KEY": "disco_..." }
    }
  }
}
```

### MCP Tools

#### Discovery workflow

| Tool | Purpose |
|------|---------|
| `discovery_upload` | Upload a dataset. Supports URL download (`file_url`), local path (`file_path`), or base64 content (`file_content`). Returns a `file_ref` for use with `discovery_analyze`. |
| `discovery_analyze` | Submit a dataset for analysis using a `file_ref` from `discovery_upload`. Returns a `run_id`. |
| `discovery_status` | Poll a running analysis by `run_id`. |
| `discovery_get_results` | Fetch completed results: patterns, p-values, citations, feature importance. |
| `discovery_estimate` | Estimate cost and time before committing to a run. |

#### Account management

| Tool | Purpose |
|------|---------|
| `discovery_signup` | Start account creation — sends verification code to email. |
| `discovery_signup_verify` | Complete signup by submitting the verification code. Returns API key. |
| `discovery_account` | Check credits, plan, and usage. |
| `discovery_list_plans` | View available plans and pricing. |
| `discovery_subscribe` | Subscribe to or change plan. |
| `discovery_purchase_credits` | Buy credit packs. |
| `discovery_add_payment_method` | Attach a Stripe payment method. |

### MCP Workflow

Analyses take 3–15 minutes. **Do not block** — submit, continue other work, poll for completion.

```
1. discovery_estimate     → Check cost/time (always do this for private runs)
2. discovery_upload       → Upload the dataset, get file_ref
3. discovery_analyze      → Submit for analysis using file_ref, get run_id
4. discovery_status       → Poll until status is "completed"
                            Returns: status, queue_position, current_step,
                            estimated_seconds, estimated_wait_seconds
5. discovery_get_results  → Fetch patterns, summary, feature importance
```

### Getting Data In

Choose the right path for your situation:

| Situation | Best approach |
|-----------|--------------|
| Data is at an http/https URL | `file_url` in `discovery_upload` |
| Local file, Python available | Python SDK (`engine.discover(...)`) |
| Local file, MCP server running locally | `file_path` in `discovery_upload` |
| Local file, hosted MCP, no Python | Direct upload API (3 steps — see below) |
| Tiny file already in memory | `file_content` in `discovery_upload` (last resort) |

---

**Data at a URL:**

```
discovery_upload(file_url="https://example.com/dataset.csv")
→ {"file": {...}, "columns": [{"name": "col1", "type": "continuous"}, ...], "rowCount": 5000}

discovery_analyze(file_ref=<result above>, target_column="outcome")
```

The server downloads the file directly — nothing passes through the agent or the model context. Works with public URLs, S3 presigned URLs, or any accessible http/https link.

---

**Local file — Python SDK** (recommended for any local file):

```python
from discovery import Engine

engine = Engine(api_key="disco_...")
result = await engine.discover("data.csv", target_column="outcome")
```

Handles upload, polling, and results in one call. No size limit. See the **Python SDK** section for full documentation.

---

**Local file — MCP server running locally** (cloned from GitHub, stdio transport):

If you've cloned the repo and are running `server.py` locally, the process can read your filesystem directly:

```
discovery_upload(file_path="/home/user/data/dataset.csv")
→ {"file": {...}, "columns": [...], "rowCount": 5000}

discovery_analyze(file_ref=<result above>, target_column="outcome")
```

Reads the file locally and streams it directly to cloud storage — nothing passes through the model context. No size limit. **`file_path` is silently ignored by the hosted server at `disco.leap-labs.com/mcp`** — it only works with a locally-running server.

---

**Local file — hosted MCP, direct upload** (works from any language):

If you're using the hosted MCP server and Python isn't available, you can upload directly via the REST API in three steps, then pass the result to `discovery_analyze` as normal.

```bash
# 1. Get a presigned upload URL
curl -X POST https://disco.leap-labs.com/api/data/upload/presign \
  -H "Authorization: Bearer disco_..." \
  -H "Content-Type: application/json" \
  -d '{"fileName": "data.csv", "contentType": "text/csv", "fileSize": 1048576}'
# → {"uploadUrl": "https://storage.googleapis.com/...", "key": "uploads/abc/data.csv", "uploadToken": "tok_..."}

# 2. PUT the file directly to cloud storage (the uploadUrl is pre-signed — no auth header needed)
curl -X PUT "<uploadUrl from step 1>" \
  -H "Content-Type: text/csv" \
  --data-binary @data.csv

# 3. Finalize the upload
curl -X POST https://disco.leap-labs.com/api/data/upload/finalize \
  -H "Authorization: Bearer disco_..." \
  -H "Content-Type: application/json" \
  -d '{"key": "uploads/abc/data.csv", "uploadToken": "tok_..."}'
# → {"ok": true, "file": {...}, "columns": [...], "rowCount": 5000}
```

Pass the finalize response directly to `discovery_analyze` as `file_ref`. No size limit.

---

**Last resort — tiny file already in memory:**

Only use this if the file is already loaded into memory and none of the above options apply. The base64-encoded content passes through the model's context window, so this only works for very small files.

```python
import base64
content = base64.b64encode(open("data.csv", "rb").read()).decode()
```

```
discovery_upload(file_content=content, file_name="data.csv")
→ {"file": {...}, "columns": [...], "rowCount": 500}

discovery_analyze(file_ref=<result above>, target_column="outcome")
```

---

### MCP Parameters

**`discovery_upload`:**

Provide exactly one of `file_url`, `file_path`, or `file_content`.

- `file_url` — http/https URL. The server downloads it directly. Best option for hosted MCP.
- `file_path` — Absolute path to a local file. **Only works when the MCP server is running locally.** Silently ignored by the hosted server.
- `file_content` — File contents, base64-encoded. **Last resort only** — the content passes through the model's context window, so this only works for very small files.
- `file_name` — Filename with extension (e.g. `"data.csv"`), used for format detection. Required with `file_content`. Default: `"data.csv"`.

Returns a `file_ref` (pass it directly to `discovery_analyze`) and `columns` (list of column names and types, useful if you need to inspect before choosing a target column).

**`discovery_analyze`:**
- `file_ref` — File reference returned by `discovery_upload`. Required.
- `target_column` — The column to predict/explain
- `depth_iterations` — 1 = fast (default), higher = deeper search. Max: num_columns - 2
- `visibility` — `"public"` (free, results published) or `"private"` (costs credits)
- `column_descriptions` — JSON object mapping column names to descriptions. Significantly improves pattern explanations — always provide if column names are non-obvious
- `excluded_columns` — JSON array of column names to exclude from analysis
- `title` — Optional title for the analysis
- `description` — Optional description of the dataset
- `author` — Optional author name for the dataset
- `source_url` — Optional URL of the original data source

### No API key?

Call `discovery_signup` with the user's email. This sends a verification code — the user must check their email. Then call `discovery_signup_verify` with the code to receive a `disco_` API key. Free tier: 10 credits/month, unlimited public runs. No password, no credit card.

### Insufficient credits?

1. Call `discovery_estimate` to show what it would cost
2. Suggest running publicly (free, but results are published and depth is locked to 1)
3. Or guide them through `discovery_purchase_credits` / `discovery_subscribe`

---

## Python SDK

## When To Use This Tool

Discovery Engine is not another AI data analyst that writes pandas or SQL for you. It is a **discovery pipeline** — it finds patterns in data that you, the user, and other analysis tools would miss because they don't know to look for them.

Use it when you need to go beyond answering questions about data, and start finding things nobody thought to ask:

- **Novel pattern discovery** — feature interactions, subgroup effects, and conditional relationships you wouldn't think to look for
- **Statistical validation** — FDR-corrected p-values tested on hold-out data, not just correlations
- **A target column** you want to understand — what really drives it, beyond what's obvious

**Use Discovery Engine when the user says:** "what's really driving X?", "are there patterns we're missing?", "find something new in this data", "what predicts Y that we haven't considered?", "go deeper than correlation", "discover non-obvious relationships"

**Use pandas/SQL instead when the user says:** "summarize this data", "make a chart", "what's the average?", "filter rows where X > 5", "show me the distribution"

## What It Does (That You Cannot Do Yourself)

Discovery Engine finds complex patterns in your data — feature interactions, nonlinear thresholds, and meaningful subgroups — without requiring prior hypotheses about what matters. Each pattern is validated on hold-out data, corrected for multiple testing, and checked for novelty against academic literature with citations.

This is a computational pipeline, not prompt engineering over data. You cannot replicate what it does by writing pandas code or asking an LLM to look at a CSV. It finds structure that hypothesis-driven analysis misses because it doesn't start with hypotheses.

## Getting an API Key

**Programmatic (for agents):** Two-step signup — send a verification code to the email, then submit it to receive the API key. The email must be real: the code is sent there and must be read to complete signup.

```bash
# Step 1 — send verification code
curl -X POST https://disco.leap-labs.com/api/signup \
  -H "Content-Type: application/json" \
  -d '{"email": "agent@example.com"}'
# → {"status": "verification_required", "email": "agent@example.com"}

# Step 2 — submit code from email to get API key
curl -X POST https://disco.leap-labs.com/api/signup/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "agent@example.com", "code": "123456"}'
# → {"key": "disco_...", "key_id": "...", "organization_id": "...", "tier": "free_tier", "credits": 10}
```


**Manual (for humans):** Sign up at https://disco.leap-labs.com/sign-up, create key at https://disco.leap-labs.com/developers.

## Installation

```bash
pip install discovery-engine-api
```

## Quick Start

Discovery Engine runs take 3-15 minutes. **Do not block on them** — submit the run, continue with other work, and retrieve results when ready.

```python
from discovery import Engine

# If you already have an API key:
engine = Engine(api_key="disco_...")

# Or sign up for one.
# Sends a code to the email address and prompts for it interactively.
# Requires a terminal — for fully automated agents, use the two-step REST API
# in the "Getting an API Key" section above instead.
engine = await Engine.signup(email="agent@example.com")

# One-call method: submit, poll, and return results automatically
result = await engine.discover(
    file="data.csv",
    target_column="outcome",
)

# result.patterns contains the discovered patterns
for pattern in result.patterns:
    if pattern.p_value < 0.05 and pattern.novelty_type == "novel":
        print(f"{pattern.description} (p={pattern.p_value:.4f})")
```

### Inspecting Columns Before Running

If you need to see the dataset's columns before choosing a target column, upload first and inspect:

```python
# Upload once and get the server's parsed column list
upload = await engine.upload_file(file="data.csv", title="My dataset")
print(upload["columns"])   # [{"name": "col1", "type": "continuous", ...}, ...]
print(upload["rowCount"])  # e.g., 5000

# Pass the result to avoid re-uploading
result = await engine.run_async(
    file="data.csv",
    target_column="col1",
    wait=True,
    upload_result=upload,  # skips the upload step
)
```

### Running in the Background

If you need to do other work while Discovery Engine runs (recommended for agent workflows):

```python
# Submit and return immediately (wait=False is the default for run_async)
run = await engine.run_async(file="data.csv", target_column="outcome")
print(f"Submitted run {run.run_id}, continuing with other work...")

# ... do other things ...

# Check back later
result = await engine.wait_for_completion(run.run_id, timeout=1800)
```

This is the preferred pattern for agents. `engine.discover()` is a convenience wrapper that does this internally with `wait=True`.

**Non-async contexts:** use `engine.discover_sync()` — same signature as `discover()`, runs in a managed event loop.

## Example Output

Here's a truncated real response from a crop yield analysis (target column: `yield_tons_per_hectare`). This is what `engine.discover()` returns:

```python
EngineResult(
    run_id="a1b2c3d4-...",
    status="completed",
    task="regression",
    total_rows=5012,
    report_url="https://disco.leap-labs.com/reports/a1b2c3d4-...",

    summary=Summary(
        overview="Discovery Engine identified 14 statistically significant patterns in this "
                 "agricultural dataset. 5 patterns are novel — not reported in existing literature. "
                 "The strongest driver of crop yield is a previously unreported interaction between "
                 "humidity and wind speed at specific thresholds.",
        key_insights=[
            "Humidity alone is a known predictor, but the interaction with low wind speed at "
            "72-89% humidity produces a 34% yield increase — a novel finding.",
            "Soil nitrogen above 45 mg/kg shows diminishing returns when phosphorus is below "
            "12 mg/kg, contradicting standard fertilization guidelines.",
            "Planting density has a non-linear effect: the optimal range (35-42 plants/m²) is "
            "narrower than current recommendations suggest.",
        ],
        novel_patterns=PatternGroup(
            pattern_ids=["p-1", "p-2", "p-5", "p-9", "p-12"],
            explanation="5 of 14 patterns have not been reported in the agricultural literature. "
                        "The humidity × wind interaction (p-1) and the nitrogen-phosphorus "
                        "diminishing returns effect (p-2) are the most significant novel findings."
        ),
    ),

    patterns=[
        # Pattern 1: Novel multi-condition interaction
        Pattern(
            id="p-1",
            task="regression",
            target_column="yield_tons_per_hectare",
            description="When humidity is between 72-89% AND wind speed is below 12 km/h, "
                        "crop yield increases by 34% above the dataset average",
            conditions=[
                {"type": "continuous", "feature": "humidity_pct",
                 "min_value": 72.0, "max_value": 89.0, "min_q": 0.55, "max_q": 0.88},
                {"type": "continuous", "feature": "wind_speed_kmh",
                 "min_value": 0.0, "max_value": 12.0, "min_q": 0.0, "max_q": 0.41},
            ],
            p_value=0.003,                     # FDR-corrected
            p_value_raw=0.0004,
            novelty_type="novel",
            novelty_explanation="Published studies examine humidity and wind speed as independent "
                                "predictors of crop yield, but this interaction effect — where "
                                "low wind amplifies the benefit of high humidity within a specific "
                                "range — has not been reported in the literature.",
            citations=[
                {"title": "Effects of relative humidity on cereal crop productivity",
                 "authors": ["Zhang, L.", "Wang, H."], "year": "2021",
                 "journal": "Journal of Agricultural Science", "doi": "10.1017/S0021859621000..."},
                {"title": "Wind exposure and grain yield: a meta-analysis",
                 "authors": ["Patel, R.", "Singh, K."], "year": "2019",
                 "journal": "Field Crops Research", "doi": "10.1016/j.fcr.2019.03..."},
            ],
            target_change_direction="max",
            abs_target_change=0.34,
            target_score=0.81,
            support_count=847,
            support_percentage=16.9,
            target_mean=8.7,
            target_std=1.2,
        ),

        # Pattern 2: Novel — contradicts existing guidelines
        Pattern(
            id="p-2",
            task="regression",
            target_column="yield_tons_per_hectare",
            description="When soil nitrogen exceeds 45 mg/kg AND soil phosphorus is below "
                        "12 mg/kg, crop yield decreases by 18% — a diminishing returns effect "
                        "not captured by standard fertilization models",
            conditions=[
                {"type": "continuous", "feature": "soil_nitrogen_mg_kg",
                 "min_value": 45.0, "max_value": 98.0, "min_q": 0.72, "max_q": 1.0},
                {"type": "continuous", "feature": "soil_phosphorus_mg_kg",
                 "min_value": 1.0, "max_value": 12.0, "min_q": 0.0, "max_q": 0.31},
            ],
            p_value=0.008,
            p_value_raw=0.0012,
            novelty_type="novel",
            novelty_explanation="Nitrogen-phosphorus balance is studied extensively, but the "
                                "specific threshold at which high nitrogen becomes counterproductive "
                                "under low phosphorus conditions has not been quantified in field studies.",
            citations=[
                {"title": "Nitrogen-phosphorus interactions in cereal cropping systems",
                 "authors": ["Mueller, T.", "Fischer, A."], "year": "2020",
                 "journal": "Nutrient Cycling in Agroecosystems", "doi": "10.1007/s10705-020-..."},
            ],
            target_change_direction="min",
            abs_target_change=0.18,
            target_score=0.74,
            support_count=634,
            support_percentage=12.7,
            target_mean=5.3,
            target_std=1.8,
        ),

        # Pattern 3: Confirmatory — validates known finding
        Pattern(
            id="p-3",
            task="regression",
            target_column="yield_tons_per_hectare",
            description="When soil organic matter is above 3.2% AND irrigation is 'drip', "
                        "crop yield increases by 22%",
            conditions=[
                {"type": "continuous", "feature": "soil_organic_matter_pct",
                 "min_value": 3.2, "max_value": 7.1, "min_q": 0.61, "max_q": 1.0},
                {"type": "categorical", "feature": "irrigation_type",
                 "values": ["drip"]},
            ],
            p_value=0.001,
            p_value_raw=0.0001,
            novelty_type="confirmatory",
            novelty_explanation="The positive interaction between soil organic matter and drip "
                                "irrigation efficiency is well-documented in the literature.",
            citations=[
                {"title": "Drip irrigation and soil health: a systematic review",
                 "authors": ["Kumar, S.", "Patel, A."], "year": "2022",
                 "journal": "Agricultural Water Management", "doi": "10.1016/j.agwat.2022..."},
            ],
            target_change_direction="max",
            abs_target_change=0.22,
            target_score=0.69,
            support_count=1203,
            support_percentage=24.0,
            target_mean=7.9,
            target_std=1.5,
        ),

        # ... 11 more patterns omitted
    ],

    feature_importance=FeatureImportance(
        kind="global",
        baseline=6.5,          # Mean yield across the dataset
        scores=[
            FeatureImportanceScore(feature="humidity_pct", score=1.82),
            FeatureImportanceScore(feature="soil_nitrogen_mg_kg", score=1.45),
            FeatureImportanceScore(feature="soil_organic_matter_pct", score=1.21),
            FeatureImportanceScore(feature="irrigation_type", score=0.94),
            FeatureImportanceScore(feature="wind_speed_kmh", score=-0.67),
            FeatureImportanceScore(feature="planting_density_per_m2", score=0.58),
            # ... more features
        ],
    ),

    columns=[
        Column(name="yield_tons_per_hectare", type="continuous", data_type="float",
               mean=6.5, median=6.2, std=2.1, min=1.1, max=14.3),
        Column(name="humidity_pct", type="continuous", data_type="float",
               mean=65.3, median=67.0, std=18.2, min=12.0, max=99.0),
        Column(name="irrigation_type", type="categorical", data_type="string",
               approx_unique=4, mode="furrow"),
        # ... more columns
    ],
)
```

Key things to notice:
- **Patterns are combinations of conditions** (humidity AND wind speed), not single correlations
- **Specific threshold ranges** (72-89%), not just "higher humidity is better"
- **Novel vs confirmatory**: each pattern is classified and explained — novel findings are what you came for, confirmatory ones validate known science
- **Citations** show what IS known, so you can see what's genuinely new
- **Summary** gives the agent a narrative to present to the user immediately
- **`report_url`** links to an interactive web report — drop this in your response so the user can explore visually

## Parameters

```python
engine.discover(
    file: str | Path | pd.DataFrame,  # Dataset to analyze
    target_column: str,                 # Column to predict/analyze
    depth_iterations: int = 1,          # 1=fast, higher=deeper search (max: num_columns - 2)
    visibility: str = "public",         # "public" (free, results will be published) or "private" (costs credits)
    title: str | None = None,           # Dataset title
    description: str | None = None,     # Dataset description
    column_descriptions: dict[str, str] | None = None,  # Column descriptions for better pattern explanations
    excluded_columns: list[str] | None = None,           # Columns to exclude from analysis
    timeout: float = 1800,              # Max seconds to wait for completion
)
```

**Tip:** Providing `column_descriptions` significantly improves pattern explanations. If your columns have non-obvious names (e.g., `col_7`, `feat_a`), always describe them.

## Cost

- **Public runs**: Free. Results published to public gallery. Locked to depth=1.
- **Private runs**: 1 credit per MB per depth iteration. $1.00 per credit.
- Formula: `credits = max(1, ceil(file_size_mb * depth_iterations))`
- API keys: https://disco.leap-labs.com/developers
- Credits: https://disco.leap-labs.com/account

## Paying for Credits (Programmatic)

Agents can attach a payment method and purchase credits entirely via the API — no browser required.

**Step 1 — Get your Stripe publishable key**

```python
account = await engine.get_account()
stripe_pk = account["stripe_publishable_key"]
stripe_customer_id = account["stripe_customer_id"]
```

Or via REST:

```bash
curl https://disco.leap-labs.com/api/account \
  -H "Authorization: Bearer disco_..."
# → { "stripe_publishable_key": "pk_live_...", "stripe_customer_id": "cus_...", "credits": {...}, ... }
```

**Step 2 — Tokenize a card using the Stripe API**

Use the publishable key to create a Stripe PaymentMethod. Card data goes directly to Stripe — Discovery Engine never sees it.

```python
import requests

pm_response = requests.post(
    "https://api.stripe.com/v1/payment_methods",
    auth=(stripe_pk, ""),  # publishable key as username, empty password
    data={
        "type": "card",
        "card[number]": "4242424242424242",
        "card[exp_month]": "12",
        "card[exp_year]": "2028",
        "card[cvc]": "123",
    },
)
payment_method_id = pm_response.json()["id"]  # "pm_..."
```

**Step 3 — Attach the payment method**

```python
result = await engine.add_payment_method(payment_method_id)
# → {"payment_method_attached": True, "card_last4": "4242", "card_brand": "visa"}
```

Or via REST:

```bash
curl -X POST https://disco.leap-labs.com/api/account/payment-method \
  -H "Authorization: Bearer disco_..." \
  -H "Content-Type: application/json" \
  -d '{"payment_method_id": "pm_..."}'
```

**Step 4 — Purchase credits**

Credits are sold in packs of 20 ($20/pack, $1.00/credit).

```python
result = await engine.purchase_credits(packs=1)
# → {"purchased_credits": 20, "total_credits": 30, "charge_amount_usd": 20.0, "stripe_payment_id": "pi_..."}
```

Or via REST:

```bash
curl -X POST https://disco.leap-labs.com/api/account/credits/purchase \
  -H "Authorization: Bearer disco_..." \
  -H "Content-Type: application/json" \
  -d '{"packs": 1}'
```

**Subscriptions (optional)**

For regular usage, subscribe to a paid plan instead of buying packs:

```python
# Plans: free_tier ($0, 10 cr/mo), tier_1 ($49, 50 cr/mo), tier_2 ($199, 200 cr/mo)
result = await engine.subscribe(plan="tier_1")
# → {"plan": "tier_1", "name": "Researcher", "monthly_credits": 50, "price_usd": 49}
```

Requires a payment method on file. See `GET /api/plans` for full plan details.

## Estimate Before Running

Before submitting a private analysis, estimate the cost and time:

```python
estimate = await engine.estimate(
    file_size_mb=10.5,
    num_columns=25,
    num_rows=5000,                # Optional — improves time estimate accuracy
    depth_iterations=2,
    visibility="private",
)
# estimate["cost"]["credits"] → 21
# estimate["cost"]["free_alternative"] → True (run publicly for free at depth=1)
# estimate["time_estimate"]["estimated_seconds"] → 360
# estimate["account"]["sufficient"] → True/False
```

Always estimate before running private analyses. If credits are insufficient, consider running publicly (free, but results are published and depth is locked to 1).

## Result Structure

```python
@dataclass
class EngineResult:
    run_id: str
    report_id: str | None                          # Report UUID (used in report_url)
    status: str                                    # "pending", "processing", "completed", "failed"
    dataset_title: str | None                      # Title of the dataset
    dataset_description: str | None                # Description of the dataset
    total_rows: int | None
    target_column: str | None                      # Column being predicted/analyzed
    task: str | None                               # "regression", "binary_classification", "multiclass_classification"
    summary: Summary | None                        # LLM-generated insights
    patterns: list[Pattern]                        # Discovered patterns (the core output)
    columns: list[Column]                          # Feature info and statistics
    correlation_matrix: list[CorrelationEntry]     # Feature correlations
    feature_importance: FeatureImportance | None   # Global importance scores
    job_id: str | None                             # Job ID for tracking
    job_status: str | None                         # Job queue status
    queue_position: int | None                     # Position in queue when pending (1 = next up)
    current_step: str | None                       # Active pipeline step (preprocessing, training, interpreting, reporting)
    current_step_message: str | None               # Human-readable description of the current step
    estimated_seconds: int | None                  # Estimated total processing time in seconds
    estimated_wait_seconds: int | None             # Estimated queue wait time in seconds (pending only)
    error_message: str | None
    report_url: str | None                         # Shareable link to interactive web report
    hints: list[str]                               # Upgrade hints (non-empty for free-tier users with hidden patterns)
    hidden_deep_count: int                         # Patterns hidden for free-tier accounts (upgrade to see all)
    hidden_deep_novel_count: int                   # Novel patterns hidden for free-tier accounts

@dataclass
class Pattern:
    id: str
    description: str                    # Human-readable description of the pattern
    conditions: list[dict]              # Conditions defining the pattern (feature ranges/values)
    p_value: float                      # FDR-adjusted p-value (lower = more significant)
    p_value_raw: float | None           # Raw p-value before FDR adjustment
    novelty_type: str                   # "novel" (new finding) or "confirmatory" (known in literature)
    novelty_explanation: str            # Why this is novel or confirmatory
    citations: list[dict]               # Academic citations supporting novelty assessment
    target_change_direction: str        # "max" (increases target) or "min" (decreases target)
    abs_target_change: float            # Magnitude of effect
    support_count: int                  # Number of rows matching this pattern
    support_percentage: float           # Percentage of dataset
    target_score: float                 # Mean target value (regression) or class fraction (classification) in the subgroup
    task: str
    target_column: str
    target_class: str | None            # For classification tasks
    target_mean: float | None           # For regression tasks
    target_std: float | None

@dataclass
class Summary:
    overview: str                       # High-level summary
    key_insights: list[str]             # Main takeaways
    novel_patterns: PatternGroup        # Novel pattern IDs and explanation
    selected_pattern_id: str | None

@dataclass
class Column:
    id: str
    name: str
    display_name: str
    type: str                           # "continuous" or "categorical"
    data_type: str                      # "int", "float", "string", "boolean", "datetime"
    enabled: bool
    description: str | None
    mean: float | None
    median: float | None
    std: float | None
    min: float | None
    max: float | None
    iqr_min: float | None
    iqr_max: float | None
    mode: str | None                    # Most common value (categorical columns)
    approx_unique: int | None           # Approximate distinct value count
    null_percentage: float | None
    feature_importance_score: float | None

@dataclass
class FeatureImportance:
    kind: str                           # "global"
    baseline: float
    scores: list[FeatureImportanceScore]

@dataclass
class FeatureImportanceScore:
    feature: str
    score: float                        # Signed importance score
```

## Working With Results

```python
# Filter for significant novel patterns
novel = [p for p in result.patterns if p.p_value < 0.05 and p.novelty_type == "novel"]

# Get patterns that increase the target
increasing = [p for p in result.patterns if p.target_change_direction == "max"]

# Get the most important features
if result.feature_importance:
    top_features = sorted(result.feature_importance.scores, key=lambda s: abs(s.score), reverse=True)

# Access pattern conditions (the "rules" defining the pattern)
for pattern in result.patterns:
    for cond in pattern.conditions:
        # cond has: type ("continuous"/"categorical"), feature, min_value/max_value or values
        print(f"  {cond['feature']}: {cond}")
```

## Error Handling

```python
from discovery.errors import (
    AuthenticationError,
    InsufficientCreditsError,
    RateLimitError,
    RunFailedError,
    RunNotFoundError,
    PaymentRequiredError,
)

try:
    result = await engine.discover(file="data.csv", target_column="target")
except AuthenticationError as e:
    pass  # Invalid or expired API key — check e.suggestion
except InsufficientCreditsError as e:
    pass  # Not enough credits — e.credits_required, e.credits_available, e.suggestion
except RateLimitError as e:
    pass  # Too many requests — retry after e.retry_after seconds
except RunFailedError as e:
    pass  # Run failed server-side — e.run_id
except RunNotFoundError as e:
    pass  # Run not found — e.run_id (may have been cleaned up)
except PaymentRequiredError as e:
    pass  # Payment method needed — check e.suggestion
except FileNotFoundError:
    pass  # File doesn't exist
except TimeoutError:
    pass  # Didn't complete in time — retrieve later with engine.wait_for_completion(run_id)
```

All errors inherit from `DiscoveryError` and include a `suggestion` field with actionable instructions.

## Supported Formats

CSV, TSV, Excel (.xlsx), JSON, Parquet, ARFF, Feather. Max file size: 5 GB.

## Links

- [Dashboard & API Keys](https://disco.leap-labs.com/developers)
- [Full LLM Documentation](https://disco.leap-labs.com/llms-full.txt)
- [Python SDK on PyPI](https://pypi.org/project/discovery-engine-api/)
- [API Spec](https://disco.leap-labs.com/.well-known/openapi.json)