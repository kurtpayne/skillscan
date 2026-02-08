# Detection Rules and Verdict Logic

## Core detection rules

Current built-in IDs:

1. `MAL-001` (critical): download-and-exec patterns such as `curl|bash`.
2. `MAL-002` (high): base64 decode plus execution patterns.
3. `ABU-001` (high): coercive instruction text (for example disabling security controls).
4. `EXF-001` (high): sensitive credential file access markers.
5. `IOC-001` (high): IOC matched against local intel blocklists (domain, URL, IP, or CIDR netblock).
6. `POL-IOC-BLOCK` (high): domain matched explicit `block_domains` policy list.
7. `DEP-001` (severity from feed): vulnerable dependency version matched local vuln data.
8. `DEP-UNPIN` (medium): unpinned dependency version specification.

## Mitigation guidance by rule

1. `MAL-001`: Remove download-and-execute chains. Pin and verify artifacts before execution.
2. `MAL-002`: Remove decode-and-exec flows. Commit reviewed scripts and execute trusted local files only.
3. `ABU-001`: Remove coercive setup instructions and never require disabling host security controls.
4. `EXF-001`: Avoid direct secret-file access; use scoped secret providers and least-privilege credentials.
5. `IOC-001`: Treat as high risk, block deployment, and remove indicator references pending investigation.
6. `POL-IOC-BLOCK`: Replace blocked domains with approved endpoints or remove outbound dependency.
7. `DEP-001`: Upgrade affected package versions and regenerate lockfiles.
8. `DEP-UNPIN`: Pin exact package versions to reduce supply-chain drift and improve reproducibility.

## Capability inference rules

SkillScan also infers non-verdict capabilities from pattern matches:

1. `shell_execution`
2. `network_access`
3. `filesystem_write`

## Scoring model

Each finding has a severity base score:

- low: 5
- medium: 15
- high: 35
- critical: 60

Final score is the sum of `severity_score * policy_category_weight`.

## Built-in policy profiles

### strict (default)

- warn: `>=30`
- block: `>=70`
- hard blocks: `MAL-001`, `IOC-001`

### balanced

- warn: `>=50`
- block: `>=120`
- hard blocks: `MAL-001`

### permissive

- warn: `>=90`
- block: `>=190`
- hard blocks: none

## Verdict order

1. If any hard-block rule is present => `block`
2. Else if score >= block threshold => `block`
3. Else if score >= warn threshold => `warn`
4. Else => `allow`
