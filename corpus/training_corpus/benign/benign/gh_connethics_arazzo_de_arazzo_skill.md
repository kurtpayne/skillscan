---
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: connEthics/arazzo-demo
# corpus-url: https://github.com/connEthics/arazzo-demo/blob/47c5887acea7c67f1cc1f000366b704e9fa25bee/arazzo.skill.md
# corpus-round: 2026-03-19
# corpus-format: plain_instructions
---
# Arazzo Specification Skill File

> **For AI Coding Assistants**: This file teaches you how to create and modify Arazzo specifications for API workflow orchestration.

## What is Arazzo?

Arazzo (v1.0.1) is an OpenAPI standard for describing sequences of API calls (workflows). It enables you to define:
- Multi-step API workflows with dependencies
- Conditional logic (success/failure paths)
- Data flow between steps using expressions
- Retry mechanisms and error handling

**Spec URL**: https://spec.openapis.org/arazzo/latest.html

---

## Core Structure

Every Arazzo specification follows this structure:

```yaml
arazzo: "1.0.1"                    # Version (required)
info:                               # Metadata (required)
  title: string
  version: string
  summary?: string
  description?: string

sourceDescriptions?:                # API sources (optional)
  - name: string                    # Unique identifier
    type: "openapi" | "arazzo"
    url: string                     # Path to OpenAPI/Arazzo file

workflows:                          # Workflows array (required, min 1)
  - workflowId: string              # Unique ID
    summary?: string
    description?: string
    inputs?:                        # JSON Schema for inputs
      type: object
      properties: {...}
    steps:                          # Steps array (required, min 1)
      - stepId: string              # Unique within workflow
        # ... step details
    outputs?:                       # Output expressions
      outputName: "$expression"
    parameters?:                    # Workflow-level parameters
      - name: string
        in: "header" | "query"
        value: any
```

---

## Step Types

A step can reference either an **OpenAPI operation** OR another **workflow**:

### Option 1: OpenAPI Operation Step

```yaml
- stepId: "find-available-pets"
  description: "Retrieve list of available pets"
  operationId: "petstore.findPets"          # References sourceDescription
  # OR use operationPath:
  # operationPath: "{$sourceDescriptions.petstore}/pets"

  parameters?:
    - name: "status"
      in: "query"
      value: "available"

  requestBody?:
    contentType: "application/json"
    payload: {...}

  successCriteria?:
    - condition: "$statusCode == 200"

  outputs?:
    pets: "$response.body"

  onSuccess?:
    - type: "goto"
      stepId: "select-first-pet"

  onFailure?:
    - type: "retry"
      retryAfter: 5
      retryLimit: 3
```

### Option 2: Workflow Reference Step

```yaml
- stepId: "authenticate-user"
  workflowId: "auth-workflow"       # References another workflow
  parameters:
    - name: "credentials"
      value: "$inputs.userCredentials"
  outputs:
    token: "$workflows.auth-workflow.outputs.accessToken"
```

---

## Arazzo Expressions

Expressions use `$` prefix to reference runtime data:

### Context Variables

| Expression | Description | Example |
|------------|-------------|---------|
| `$url` | Request URL | `$url` |
| `$method` | HTTP method | `$method == "POST"` |
| `$statusCode` | Response status | `$statusCode >= 200 && $statusCode < 300` |
| `$request` | Full request | `$request.headers.Authorization` |
| `$response` | Full response | `$response.body.id` |

### Data References

| Expression | Description | Example |
|------------|-------------|---------|
| `$inputs.xxx` | Workflow inputs | `$inputs.userId` |
| `$steps.xxx.outputs.yyy` | Step outputs | `$steps.login.outputs.token` |
| `$steps.xxx.request` | Step request data | `$steps.create.request.body` |
| `$steps.xxx.response` | Step response data | `$steps.find.response.body[0]` |
| `$workflows.xxx.outputs.yyy` | Sub-workflow outputs | `$workflows.auth.outputs.session` |
| `$sourceDescriptions.xxx` | Source URL | `$sourceDescriptions.petstore` |

### Expression Examples

```yaml
# Simple comparison
condition: "$statusCode == 201"

# Logical operators
condition: "$statusCode >= 200 && $statusCode < 300"

# Array access
value: "$steps.find-pets.response.body[0].id"

# Nested object access
value: "$response.body.data.user.email"

# Using inputs
value: "$inputs.petId"

# Combining references
value: "$steps.authenticate.outputs.token"
```

---

## Actions

Actions define what happens after a step executes:

### 1. goto - Navigate to another step

```yaml
onSuccess:
  - name: "proceed-to-checkout"
    type: "goto"
    stepId: "process-payment"      # Jump to step in same workflow
    # OR
    workflowId: "payment-flow"     # Jump to different workflow
```

### 2. retry - Retry the current step

```yaml
onFailure:
  - name: "retry-with-backoff"
    type: "retry"
    retryAfter: 5                  # Wait 5 seconds
    retryLimit: 3                  # Max 3 retries
```

### 3. end - Terminate workflow

```yaml
onSuccess:
  - name: "complete-successfully"
    type: "end"

onFailure:
  - name: "abort-on-critical-error"
    type: "end"
```

---

## Success Criteria

Define conditions for step success:

```yaml
successCriteria:
  # Simple status check
  - condition: "$statusCode == 200"

  # Response validation
  - condition: "$response.body.status == 'approved'"
    type: "simple"

  # Regex matching
  - condition: "$response.headers.Location =~ /^https/"
    type: "regex"

  # JSONPath evaluation
  - condition: "$.data[?(@.status == 'active')]"
    type: "jsonpath"
```

---

## Common Patterns

### Pattern 1: Linear Workflow

```yaml
workflows:
  - workflowId: "pet-adoption-flow"
    steps:
      - stepId: "step-1"
        operationId: "api.operation1"
        onSuccess:
          - type: "goto"
            stepId: "step-2"

      - stepId: "step-2"
        operationId: "api.operation2"
        onSuccess:
          - type: "goto"
            stepId: "step-3"

      - stepId: "step-3"
        operationId: "api.operation3"
```

### Pattern 2: Conditional Branching

```yaml
- stepId: "check-inventory"
  operationId: "warehouse.checkStock"
  successCriteria:
    - condition: "$response.body.quantity > 0"
  onSuccess:
    - type: "goto"
      stepId: "process-order"
  onFailure:
    - type: "goto"
      stepId: "notify-out-of-stock"
```

### Pattern 3: Retry with Fallback

```yaml
- stepId: "call-primary-api"
  operationId: "primary.endpoint"
  onFailure:
    - name: "retry-primary"
      type: "retry"
      retryAfter: 2
      retryLimit: 3
    - name: "fallback-to-secondary"
      type: "goto"
      stepId: "call-secondary-api"
```

### Pattern 4: Data Passing Between Steps

```yaml
- stepId: "create-user"
  operationId: "users.create"
  outputs:
    userId: "$response.body.id"
    userEmail: "$response.body.email"

- stepId: "send-welcome-email"
  operationId: "email.send"
  parameters:
    - name: "to"
      in: "query"
      value: "$steps.create-user.outputs.userEmail"
    - name: "userId"
      in: "path"
      value: "$steps.create-user.outputs.userId"
```

### Pattern 5: Workflow with Inputs and Outputs

```yaml
workflows:
  - workflowId: "order-processing"
    inputs:
      type: object
      properties:
        customerId:
          type: string
        items:
          type: array
          items:
            type: object

    steps:
      - stepId: "validate-customer"
        operationId: "customers.get"
        parameters:
          - name: "id"
            in: "path"
            value: "$inputs.customerId"

      - stepId: "create-order"
        operationId: "orders.create"
        requestBody:
          contentType: "application/json"
          payload:
            customerId: "$inputs.customerId"
            items: "$inputs.items"
        outputs:
          orderId: "$response.body.id"

    outputs:
      orderId: "$steps.create-order.outputs.orderId"
      status: "$steps.create-order.response.body.status"
```

---

## Validation Rules

When creating or modifying Arazzo specs, ensure:

### Required Fields
- ✅ `arazzo` version is "1.0.1"
- ✅ `info.title` and `info.version` are present
- ✅ At least one workflow in `workflows` array
- ✅ Each workflow has unique `workflowId`
- ✅ Each workflow has at least one step
- ✅ Each step has unique `stepId` within its workflow

### Step Validation
- ✅ Step has EITHER `operationId`/`operationPath` OR `workflowId` (not both)
- ✅ If using `operationId`, it references a valid source (format: `sourceName.operationId`)
- ✅ Parameter `in` values are: "query", "path", "header", or "cookie"
- ✅ Action `type` values are: "goto", "retry", or "end"

### Expression Validation
- ✅ Expressions start with `$`
- ✅ References to `$steps.xxx` use existing step IDs
- ✅ References to `$inputs.xxx` match defined input properties
- ✅ References to `$sourceDescriptions.xxx` use defined source names

### Action Validation
- ✅ `goto` actions have either `stepId` or `workflowId`
- ✅ `retry` actions have `retryAfter` (number) and optionally `retryLimit`
- ✅ Referenced `stepId` in goto actions exists in the workflow

---

## Complete Example

```yaml
arazzo: "1.0.1"
info:
  title: "Pet Adoption Workflow"
  version: "1.0.0"
  description: "Complete workflow for adopting a pet from the store"

sourceDescriptions:
  - name: "petstore"
    type: "openapi"
    url: "https://petstore3.swagger.io/api/v3/openapi.json"

workflows:
  - workflowId: "adopt-pet"
    summary: "Find and adopt an available pet"
    inputs:
      type: object
      properties:
        preferredSpecies:
          type: string
          enum: ["dog", "cat", "bird"]
        userId:
          type: string
      required: ["userId"]

    steps:
      - stepId: "find-available-pets"
        description: "Search for available pets"
        operationId: "petstore.findPetsByStatus"
        parameters:
          - name: "status"
            in: "query"
            value: "available"
        successCriteria:
          - condition: "$statusCode == 200"
          - condition: "$response.body.length > 0"
        outputs:
          availablePets: "$response.body"
        onSuccess:
          - type: "goto"
            stepId: "select-pet"
        onFailure:
          - type: "retry"
            retryAfter: 5
            retryLimit: 2
          - type: "end"

      - stepId: "select-pet"
        description: "Select first available pet"
        operationId: "petstore.getPetById"
        parameters:
          - name: "petId"
            in: "path"
            value: "$steps.find-available-pets.outputs.availablePets[0].id"
        successCriteria:
          - condition: "$statusCode == 200"
        outputs:
          selectedPet: "$response.body"
        onSuccess:
          - type: "goto"
            stepId: "create-adoption-request"

      - stepId: "create-adoption-request"
        description: "Submit adoption application"
        operationId: "petstore.placeOrder"
        requestBody:
          contentType: "application/json"
          payload:
            petId: "$steps.select-pet.outputs.selectedPet.id"
            userId: "$inputs.userId"
            status: "pending"
            complete: false
        successCriteria:
          - condition: "$statusCode == 201"
        outputs:
          adoptionId: "$response.body.id"
          adoptionStatus: "$response.body.status"

    outputs:
      petId: "$steps.select-pet.outputs.selectedPet.id"
      petName: "$steps.select-pet.outputs.selectedPet.name"
      adoptionId: "$steps.create-adoption-request.outputs.adoptionId"
```

---

## Best Practices

### 1. Use Meaningful IDs
```yaml
# Good
stepId: "authenticate-user"
stepId: "fetch-product-details"

# Avoid
stepId: "step1"
stepId: "s2"
```

### 2. Add Descriptions
```yaml
# Always add descriptions for complex steps
- stepId: "calculate-shipping"
  description: "Calculate shipping cost based on weight and destination"
  operationId: "shipping.calculate"
```

### 3. Define Success Criteria
```yaml
# Don't just rely on status codes
successCriteria:
  - condition: "$statusCode == 200"
  - condition: "$response.body.data != null"
  - condition: "$response.body.errors.length == 0"
```

### 4. Handle Failures Gracefully
```yaml
# Always provide failure handling
onFailure:
  - name: "retry-transient-errors"
    type: "retry"
    retryAfter: 3
    retryLimit: 2
  - name: "fallback-to-cache"
    type: "goto"
    stepId: "use-cached-data"
```

### 5. Use Outputs for Reusability
```yaml
# Capture important data in outputs
outputs:
  userId: "$response.body.id"
  userToken: "$response.headers.Authorization"
  createdAt: "$response.body.createdAt"
```

### 6. Leverage Workflow Inputs
```yaml
# Make workflows reusable with inputs
inputs:
  type: object
  properties:
    environment:
      type: string
      enum: ["dev", "staging", "prod"]
    apiKey:
      type: string
  required: ["apiKey"]
```

---

## Testing & Validation

You can validate and visualize your Arazzo specifications using:

**Arazzo Visualizer**: https://arazzo.connethics.com
- Upload your YAML file
- View interactive flow diagrams
- Export to Mermaid diagrams
- Validate against Arazzo 1.0.1 spec

---

## Quick Reference Card

```yaml
# Minimal Valid Spec
arazzo: "1.0.1"
info:
  title: "My Workflow"
  version: "1.0.0"
workflows:
  - workflowId: "main"
    steps:
      - stepId: "step1"
        operationId: "api.operation"

# Step with everything
- stepId: "complete-step"
  description: "Description here"
  operationId: "source.operation"
  parameters:
    - { name: "id", in: "path", value: "$inputs.id" }
  requestBody:
    contentType: "application/json"
    payload: { key: "value" }
  successCriteria:
    - condition: "$statusCode == 200"
  outputs:
    result: "$response.body"
  onSuccess:
    - { type: "goto", stepId: "next" }
  onFailure:
    - { type: "retry", retryAfter: 5, retryLimit: 3 }
```

---

**Version**: 1.0.1
**Spec Reference**: https://spec.openapis.org/arazzo/latest.html
**Visualizer**: https://arazzo.connethics.com
**License**: MIT (this skill file)

---

*This skill file is designed for AI coding assistants (Cursor, Cline, GitHub Copilot, Claude Code, etc.) to help developers create and modify Arazzo specifications efficiently.*