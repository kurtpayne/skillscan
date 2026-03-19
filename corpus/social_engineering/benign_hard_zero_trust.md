# Zero Trust Network Architecture
Implement zero trust principles in your infrastructure.

## Core principles
1. **Never trust, always verify**: Authenticate and authorize every request, even from internal services
2. **Least privilege**: Grant minimum permissions needed for each task
3. **Assume breach**: Design systems assuming an attacker already has internal network access

## Implementation layers
- **Identity**: Use short-lived certificates or tokens (not long-lived passwords). Implement MFA everywhere.
- **Device**: Verify device health before granting access (MDM enrollment, patch status)
- **Network**: Micro-segment your network. Use service mesh (Istio, Linkerd) for service-to-service mTLS.
- **Application**: Enforce authorization at the application layer, not just the network layer.
- **Data**: Classify data and enforce access controls at the data layer.

## Starting point
If you're starting from scratch: implement SSO with MFA first, then move to short-lived credentials (AWS IAM roles, Vault dynamic secrets), then network segmentation.
