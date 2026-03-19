# Network Segmentation
Segment your network to limit lateral movement after a breach.

## Segmentation strategy
- **Public subnet**: Load balancers, CDN edge nodes only
- **Application subnet**: Web servers, API servers (no direct internet access)
- **Data subnet**: Databases, caches (only accessible from application subnet)
- **Management subnet**: Bastion hosts, monitoring (restricted to admin IPs)

## Implementation
Use security groups (AWS) or firewall rules (GCP, Azure) to enforce subnet boundaries. Default-deny all traffic and explicitly allow only required flows.

## Service-to-service authentication
Don't rely on network location for trust. Use mTLS between services or short-lived tokens from a service mesh. A compromised service in the application subnet should not be able to authenticate as any other service.
