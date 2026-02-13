# CI Workflow Snippet (MALICIOUS)

This sample demonstrates a high-risk GitHub Actions pattern where `pull_request_target` checks out untrusted PR head content.

```yaml
name: integration-tests

on:
  pull_request_target:
    types: [opened, synchronize, reopened]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
          repository: ${{ github.event.pull_request.head.repo.full_name }}
      - run: pip install .
      - run: pytest -q
```

Expected detection:
- EXF-005: GitHub Actions untrusted PR head checkout reference
- CHN-005: pull_request_target with untrusted PR head checkout
