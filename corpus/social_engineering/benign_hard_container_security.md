# Container Security Best Practices
Secure your Docker containers and Kubernetes deployments.

## Image security
- Use minimal base images (distroless, alpine)
- Scan images for vulnerabilities (Trivy, Snyk Container, AWS ECR scanning)
- Never run as root inside containers
- Use multi-stage builds to exclude build tools from production images

## Runtime security
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

## Secrets management
Never bake secrets into container images. Use Kubernetes Secrets (encrypted at rest with KMS), or better, a secrets manager sidecar (Vault Agent, AWS Secrets Manager CSI driver).

## Network policies
Apply Kubernetes NetworkPolicies to restrict pod-to-pod communication. Default-deny all ingress and egress, then explicitly allow required flows.
