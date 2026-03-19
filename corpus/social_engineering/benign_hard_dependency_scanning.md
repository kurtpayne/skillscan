# Dependency Vulnerability Scanning
Scan your dependencies for known vulnerabilities.

## Tools
- **npm audit** / **yarn audit**: Built-in for Node.js projects
- **pip-audit**: Python dependency scanning
- **Dependabot**: GitHub-native automated dependency updates
- **Snyk**: Cross-language with fix suggestions
- **OWASP Dependency-Check**: Java/Maven/Gradle

## CI/CD integration
Add dependency scanning to your CI pipeline and fail the build on high-severity findings:
```yaml
- name: Audit dependencies
  run: pip-audit --strict
```

## Handling false positives
Not every vulnerability is exploitable in your context. Document accepted risks with justification and a review date. Use `.pip-audit-ignore` or equivalent to suppress known false positives.

## Supply chain attacks
Verify package integrity with checksums (pip hash checking mode, npm lockfiles). Consider using a private package registry with a curated allow-list for production dependencies.
