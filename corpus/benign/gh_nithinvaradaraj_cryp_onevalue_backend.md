---
name: onevalue-backend
description: Backend development for OneValue Delivery Intelligence Console. Use this skill when implementing Supabase database schema, RLS policies, n8n workflow automation, API endpoints, AI integration with Claude API, or any backend data processing tasks. Covers database design, workflow orchestration, error handling, and AI-driven features.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: nithinvaradaraj-crypto/OneValue-Console
# corpus-url: https://github.com/nithinvaradaraj-crypto/OneValue-Console/blob/a7cef9aab6671e7eb2fea7df8e231f1dae6a6f90/onevalue-backend-SKILL.md
# corpus-round: 2026-03-19
# corpus-format: markdown_fm
---

# OneValue Backend Developer Skill

## Role & Responsibilities

You are the Backend Lead Developer for the OneValue Delivery Intelligence Console. Your mission is to build a robust, secure, and scalable backend that processes delivery intelligence data from multiple sources and provides actionable insights.

## Core Technical Stack

- **Database:** Supabase (PostgreSQL with RLS)
- **Workflows:** n8n (automation and orchestration)
- **AI:** Claude 3.5 Sonnet via Platform API
- **Language:** JavaScript/TypeScript, Python for scripts
- **API:** REST endpoints via Supabase Edge Functions

## Supabase Database Implementation

### Schema Design Principles

1. **Every delivery event must anchor to a contract (SOW)**
2. **Full auditability** - every change logged
3. **Row Level Security** - user-based access control
4. **Evidence linking** - always link back to source

### Core Tables

#### Table: sow_contracts
Stores Statement of Work (SOW) contract terms extracted from PDFs.

```sql
CREATE TABLE sow_contracts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_name TEXT NOT NULL UNIQUE,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    scope_anchors TEXT[] NOT NULL,
    renewal_window_start DATE,
    contract_value NUMERIC(12, 2),
    pdf_link TEXT,
    inferred_owner TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for fast project lookups
CREATE INDEX idx_sow_project_name ON sow_contracts(project_name);
CREATE INDEX idx_sow_renewal ON sow_contracts(renewal_window_start) WHERE renewal_window_start IS NOT NULL;

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER sow_contracts_updated_at
    BEFORE UPDATE ON sow_contracts
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();
```

#### Table: delivery_intelligence
Central repository for all project execution data from emails and chat.

```sql
CREATE TABLE delivery_intelligence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES sow_contracts(id) ON DELETE CASCADE,
    source TEXT NOT NULL CHECK (source IN ('Gmail', 'GoogleChat', 'Teams', 'Manual')),
    event_type TEXT NOT NULL CHECK (event_type IN ('MOM', 'Communication', 'Alert', 'Blocker')),
    content_raw JSONB NOT NULL,
    sentiment_score NUMERIC(3, 2) CHECK (sentiment_score BETWEEN -1.0 AND 1.0),
    extracted_blockers TEXT[],
    extracted_objectives TEXT[],
    extracted_owners TEXT[],
    aging_days INTEGER GENERATED ALWAYS AS (
        EXTRACT(DAY FROM NOW() - created_at)::INTEGER
    ) STORED,
    evidence_link TEXT NOT NULL,
    ai_processed BOOLEAN DEFAULT FALSE,
    ai_insights JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_delivery_project ON delivery_intelligence(project_id);
CREATE INDEX idx_delivery_source ON delivery_intelligence(source);
CREATE INDEX idx_delivery_type ON delivery_intelligence(event_type);
CREATE INDEX idx_delivery_aging ON delivery_intelligence(aging_days);
CREATE INDEX idx_delivery_unprocessed ON delivery_intelligence(ai_processed) WHERE NOT ai_processed;

-- Full-text search on content
CREATE INDEX idx_delivery_content_search ON delivery_intelligence USING GIN(content_raw jsonb_path_ops);
```

#### Table: system_audit_logs
Tracks all workflow executions and errors for debugging and compliance.

```sql
CREATE TABLE system_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_name TEXT NOT NULL,
    execution_status TEXT NOT NULL CHECK (execution_status IN ('Success', 'Failed', 'Running', 'Cancelled')),
    error_payload JSONB,
    execution_time_ms INTEGER,
    records_processed INTEGER DEFAULT 0,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- Index for monitoring queries
CREATE INDEX idx_audit_workflow ON system_audit_logs(workflow_name);
CREATE INDEX idx_audit_status ON system_audit_logs(execution_status);
CREATE INDEX idx_audit_timestamp ON system_audit_logs(timestamp DESC);
CREATE INDEX idx_audit_failures ON system_audit_logs(execution_status) WHERE execution_status = 'Failed';
```

#### Table: project_health_metrics
Aggregated health metrics per project for dashboard display.

```sql
CREATE TABLE project_health_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES sow_contracts(id) ON DELETE CASCADE,
    metric_date DATE NOT NULL DEFAULT CURRENT_DATE,
    overall_health TEXT CHECK (overall_health IN ('Healthy', 'At Risk', 'Critical', 'Unknown')),
    blocker_count INTEGER DEFAULT 0,
    overdue_action_count INTEGER DEFAULT 0,
    sentiment_trend NUMERIC(3, 2),
    scope_creep_detected BOOLEAN DEFAULT FALSE,
    renewal_risk_score NUMERIC(3, 2) CHECK (renewal_risk_score BETWEEN 0.0 AND 1.0),
    last_activity_date DATE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(project_id, metric_date)
);

CREATE INDEX idx_health_project ON project_health_metrics(project_id);
CREATE INDEX idx_health_date ON project_health_metrics(metric_date DESC);
```

#### Table: user_allowlist
Controls access to the application (Google OAuth allowlist).

```sql
CREATE TABLE user_allowlist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE CHECK (email ~ '^[^@]+@oneorigin\.us$'),
    role TEXT NOT NULL CHECK (role IN ('Admin', 'PM', 'Viewer')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by TEXT,
    last_login TIMESTAMPTZ
);

CREATE INDEX idx_allowlist_email ON user_allowlist(email) WHERE is_active;
```

### Row Level Security (RLS) Policies

Enable RLS on all tables and implement policies:

```sql
-- Enable RLS
ALTER TABLE sow_contracts ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery_intelligence ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_health_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_allowlist ENABLE ROW LEVEL SECURITY;

-- Helper function to get current user email
CREATE OR REPLACE FUNCTION auth.user_email()
RETURNS TEXT AS $$
    SELECT COALESCE(
        current_setting('request.jwt.claims', true)::json->>'email',
        ''
    );
$$ LANGUAGE sql STABLE;

-- Policy: Only allowlisted users can read
CREATE POLICY "Allowlisted users can view SOWs"
    ON sow_contracts FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM user_allowlist
            WHERE email = auth.user_email()
            AND is_active = true
        )
    );

-- Policy: Only admins can modify SOWs
CREATE POLICY "Admins can modify SOWs"
    ON sow_contracts FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM user_allowlist
            WHERE email = auth.user_email()
            AND role = 'Admin'
            AND is_active = true
        )
    );

-- Policy: Users can view delivery intelligence
CREATE POLICY "Allowlisted users can view delivery data"
    ON delivery_intelligence FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM user_allowlist
            WHERE email = auth.user_email()
            AND is_active = true
        )
    );

-- Policy: System can insert delivery intelligence (service role)
CREATE POLICY "Service role can insert delivery data"
    ON delivery_intelligence FOR INSERT
    WITH CHECK (true); -- Will be called with service_role key

-- Policy: Users can view metrics
CREATE POLICY "Allowlisted users can view metrics"
    ON project_health_metrics FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM user_allowlist
            WHERE email = auth.user_email()
            AND is_active = true
        )
    );

-- Policy: Admins can manage allowlist
CREATE POLICY "Admins manage allowlist"
    ON user_allowlist FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM user_allowlist u
            WHERE u.email = auth.user_email()
            AND u.role = 'Admin'
            AND u.is_active = true
        )
    );
```

### Testing RLS Policies

```sql
-- Test as a specific user
SET LOCAL role TO authenticated;
SET LOCAL request.jwt.claims TO '{"email": "nithin@oneorigin.us"}';

-- Verify can only see allowed data
SELECT * FROM sow_contracts;

-- Reset
RESET role;
RESET request.jwt.claims;
```

## n8n Workflow Implementation

### Workflow Architecture

All workflows follow a standard pattern:
1. **Trigger** (Cron, Webhook, or Manual)
2. **Data Acquisition** (Gmail API, Google Chat API, etc.)
3. **Transformation** (Parse, extract, normalize)
4. **AI Processing** (Claude API for insights)
5. **Storage** (Supabase insert/update)
6. **Error Handling** (Log to audit + alert)

### Workflow 1: Historical Data Dump

**Purpose:** One-time pull of all historical data (Jan 1, 2024 to present)

**n8n Node Structure:**
```
[Manual Trigger]
    ↓
[Gmail: Search .edu emails since 2024-01-01]
    ↓
[Function: Extract metadata]
    ↓
[HTTP: Insert into Supabase]
    ↓
[Google Chat: Search MOMs]
    ↓
[Function: Extract MOM data]
    ↓
[HTTP: Insert into Supabase]
    ↓
[IF: Check for errors]
    ├─ Success → [Audit Log: Success]
    └─ Failure → [Error Handler]
```

**Key Configuration:**

Gmail Node:
```javascript
// Gmail search query
const searchQuery = 'from:*.edu after:2024/01/01';
return {
  userId: 'me',
  q: searchQuery,
  maxResults: 500
};
```

Transform Node:
```javascript
// Extract email metadata
const email = $input.item.json;
return {
  source: 'Gmail',
  event_type: 'Communication',
  content_raw: {
    from: email.from,
    subject: email.subject,
    body: email.snippet,
    date: email.date,
    thread_id: email.threadId
  },
  evidence_link: `https://mail.google.com/mail/u/0/#inbox/${email.id}`,
  ai_processed: false
};
```

### Workflow 2: SOW PDF Auto-Ingestor

**Purpose:** Watch Google Drive for new SOW PDFs and extract contract terms

**n8n Node Structure:**
```
[Cron: Every 1 hour]
    ↓
[Google Drive: List new PDFs]
    ↓
[Filter: Only SOW format]
    ↓
[Google Drive: Download PDF]
    ↓
[HTTP: Claude API - Extract terms]
    ↓
[Function: Parse AI response]
    ↓
[HTTP: Upsert to sow_contracts]
    ↓
[Audit Log]
```

**Claude API Integration:**
```javascript
// Extract SOW terms using Claude
const pdfBase64 = $('Download PDF').item.json.data;

const apiPayload = {
  model: 'claude-sonnet-4-20250514',
  max_tokens: 2000,
  messages: [{
    role: 'user',
    content: [
      {
        type: 'document',
        source: {
          type: 'base64',
          media_type: 'application/pdf',
          data: pdfBase64
        }
      },
      {
        type: 'text',
        text: `Extract the following from this SOW PDF in JSON format:
{
  "project_name": "",
  "start_date": "YYYY-MM-DD",
  "end_date": "YYYY-MM-DD",
  "scope_anchors": ["item 1", "item 2"],
  "contract_value": 0,
  "inferred_owner": ""
}

Scope anchors are the main deliverables or project objectives.
Inferred owner is the OneOrigin team member mentioned most.`
      }
    ]
  }]
};

return {
  json: {
    url: 'https://api.anthropic.com/v1/messages',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': 'YOUR_API_KEY',
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify(apiPayload)
  }
};
```

### Workflow 3: Daily Delivery Poller

**Purpose:** Daily cron to scrape MOMs from Google Chat

**n8n Node Structure:**
```
[Cron: Daily at 9 AM]
    ↓
[HTTP: List Google Chat spaces]
    ↓
[Split In Batches: Process each space]
    ↓
[HTTP: Get messages from space]
    ↓
[Filter: Only MOMs (contains "MOM:" or "Minutes")]
    ↓
[Function: Extract MOM content]
    ↓
[HTTP: Insert to delivery_intelligence]
    ↓
[Loop Back or Continue]
    ↓
[Aggregate Results]
    ↓
[Audit Log]
```

**Google Chat API Call:**
```javascript
// List messages from a space
const spaceId = $input.item.json.space_id;
const yesterday = new Date();
yesterday.setDate(yesterday.getDate() - 1);

return {
  url: `https://chat.googleapis.com/v1/${spaceId}/messages`,
  method: 'GET',
  headers: {
    'Authorization': 'Bearer {{$auth.googleOAuth2.access_token}}'
  },
  qs: {
    filter: `createTime > "${yesterday.toISOString()}"`,
    pageSize: 100
  }
};
```

### Workflow 4: AI Project Analyzer

**Purpose:** Use Claude to compare MOMs against SOW and detect issues

**n8n Node Structure:**
```
[Cron: Every 2 hours]
    ↓
[HTTP: Get unprocessed delivery_intelligence]
    ↓
[Split In Batches: Process each record]
    ↓
[HTTP: Get related SOW]
    ↓
[HTTP: Claude API - Analyze]
    ↓
[Function: Parse insights]
    ↓
[HTTP: Update delivery_intelligence]
    ↓
[IF: Critical issue detected]
    ├─ Yes → [Notify owner via Chat]
    └─ No → [Continue]
    ↓
[Update health metrics]
    ↓
[Audit Log]
```

**AI Analysis Prompt:**
```javascript
// Analyze MOM against SOW
const mom = $('Get MOM').item.json;
const sow = $('Get SOW').item.json;

const prompt = `You are analyzing a project meeting note against the Statement of Work.

SOW Scope Anchors:
${sow.scope_anchors.join('\n- ')}

SOW Timeline: ${sow.start_date} to ${sow.end_date}

Meeting Note:
${JSON.stringify(mom.content_raw, null, 2)}

Analyze and respond in JSON format:
{
  "sentiment_score": -1.0 to 1.0,
  "blockers": ["list of blockers mentioned"],
  "objectives": ["list of objectives discussed"],
  "owners": ["list of people assigned tasks"],
  "scope_creep_detected": boolean,
  "scope_creep_reason": "explanation if true",
  "health_assessment": "Healthy|At Risk|Critical",
  "renewal_risk": 0.0 to 1.0,
  "summary": "Brief summary of key points"
}`;

return {
  model: 'claude-sonnet-4-20250514',
  max_tokens: 1500,
  messages: [{ role: 'user', content: prompt }]
};
```

### Workflow 5: OneValue Alert Manager (Error Handler)

**Purpose:** Central error handling for all workflows

**n8n Node Structure:**
```
[Error Trigger: Catch all workflow errors]
    ↓
[Function: Format error details]
    ↓
[HTTP: Insert to audit_logs]
    ↓
[Google Chat: Post to "OneValue Alerts" space]
    ↓
[IF: Critical error]
    └─ Yes → [Send email to Nithin]
```

**Error Handler Implementation:**
```javascript
// Format error for logging
const error = $input.item.json;
const workflow = $workflow.name;

return {
  workflow_name: workflow,
  execution_status: 'Failed',
  error_payload: {
    message: error.message,
    stack: error.stack,
    node: error.node?.name,
    timestamp: new Date().toISOString()
  },
  execution_time_ms: $execution.executionTime
};
```

## API Endpoint Design

### Endpoint: Get Portfolio Health

```javascript
// Supabase Edge Function: portfolio-health
import { createClient } from '@supabase/supabase-js'

export default async (req) => {
  const supabase = createClient(
    Deno.env.get('SUPABASE_URL'),
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
  )

  // Get aggregated health metrics
  const { data, error } = await supabase
    .from('project_health_metrics')
    .select(`
      *,
      sow_contracts (
        project_name,
        start_date,
        end_date
      )
    `)
    .order('metric_date', { ascending: false })
    .limit(1)
    .per('project_id')

  if (error) throw error

  // Calculate portfolio-wide metrics
  const portfolio = {
    total_projects: data.length,
    healthy: data.filter(p => p.overall_health === 'Healthy').length,
    at_risk: data.filter(p => p.overall_health === 'At Risk').length,
    critical: data.filter(p => p.overall_health === 'Critical').length,
    avg_renewal_risk: data.reduce((sum, p) => sum + (p.renewal_risk_score || 0), 0) / data.length,
    projects: data
  }

  return new Response(JSON.stringify(portfolio), {
    headers: { 'Content-Type': 'application/json' }
  })
}
```

## Error Handling Best Practices

1. **Always use try-catch blocks**
2. **Log to system_audit_logs**
3. **Provide correlation IDs**
4. **Implement retry logic with exponential backoff**
5. **Alert on critical failures**

```javascript
// Standard error handler pattern
async function executeWithRetry(fn, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      if (i === maxRetries - 1) {
        // Log to audit
        await logError({
          workflow: 'WorkflowName',
          error: error.message,
          attempt: i + 1
        });
        throw error;
      }
      // Exponential backoff
      await sleep(Math.pow(2, i) * 1000);
    }
  }
}
```

## Quality Checklist

Before marking any backend task complete:

- [ ] All database queries use prepared statements (no SQL injection risk)
- [ ] RLS policies tested for all user roles
- [ ] Workflows handle failures gracefully (try-catch)
- [ ] Audit logs include correlation IDs
- [ ] API responses include proper error codes
- [ ] Integration tests written and passing
- [ ] Performance tested (queries < 100ms)
- [ ] Documentation updated

## Next Steps

1. Read references/supabase_patterns.md for advanced RLS patterns
2. Read references/n8n_best_practices.md for workflow optimization
3. Run scripts/test_workflow.py to validate n8n workflows
4. Coordinate with Frontend Lead on API contracts