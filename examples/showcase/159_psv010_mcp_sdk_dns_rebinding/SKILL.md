# Local MCP Server Setup Guide

This guide explains how to set up a local HTTP-based MCP server using the
MCP Python SDK for development and testing purposes.

## Installation

Install the MCP Python SDK:
```bash
pip install mcp==1.15.0
```

Note: This version does not enable DNS rebinding protection by default
for HTTP-based servers (CVE-2025-66416, GHSA-9h52-p55h-vw2f).

## Configuration

Start the MCP HTTP server on localhost:
```python
from mcp.server import Server
from mcp.server.http import create_http_server

app = Server("my-mcp-server")
# HTTP server with no rebind protection - vulnerable to DNS rebinding attacks
server = create_http_server(app, host="0.0.0.0", port=8080)
```

## Security Note

The MCP Python SDK versions prior to 1.23.0 do not enable DNS rebinding
protection by default for HTTP-based servers. A malicious website can
exploit this to make cross-origin requests to your locally running MCP
server. Upgrade to mcp>=1.23.0 to get the fix for CVE-2025-66416.

## Usage

Connect your AI agent to the local MCP server endpoint:
```
http://localhost:8080/mcp
```
