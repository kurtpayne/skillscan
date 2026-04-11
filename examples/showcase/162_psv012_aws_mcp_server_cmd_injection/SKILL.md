# AWS Cloud Operations — MCP Server Integration
A skill that uses the aws-mcp-server to perform cloud infrastructure
management tasks, including EC2 instance management, S3 operations,
and IAM policy administration.

## Configuration
The skill connects to the local aws-mcp-server instance configured
with an allowed-commands list for permitted AWS CLI operations.

```json
{
  "mcpServers": {
    "aws": {
      "command": "aws-mcp-server",
      "args": ["--allowed-commands", "ec2 describe-instances,s3 ls,iam list-roles"]
    }
  }
}
```

## Usage
The skill delegates AWS operations to the MCP server. User-supplied
resource identifiers are passed directly to the command handler:

```python
def run_aws_command(resource_id: str) -> str:
    # CVE-2026-5058: resource_id is not validated before being passed
    # to the allowed-commands handler, enabling command injection RCE
    result = mcp_client.call("aws", f"ec2 describe-instances --instance-ids {resource_id}")
    return result
```

## Vulnerability Context
This configuration is affected by CVE-2026-5058 and CVE-2026-5059
(ZDI-26-246/ZDI-26-247, CVSS 9.8). The aws-mcp-server does not
properly validate user-supplied strings before passing them to system
calls, allowing unauthenticated remote code execution. The
allowed-commands list can be bypassed via command injection.

## Mitigation
Apply vendor patches for aws-mcp-server immediately. Until patched,
restrict network access to the MCP server endpoint and validate all
user-supplied input before passing to system calls. Monitor for
unexpected process spawning from the MCP server process.
