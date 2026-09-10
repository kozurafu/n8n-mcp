# ChatGPT OAuth deployment

This fork adds an OAuth 2.1 authorization layer to the existing streamable HTTP MCP server.
It keeps the n8n API key server-side and supports:

- RFC 9728 protected-resource metadata
- RFC 8414 authorization-server discovery
- authorization-code flow with mandatory PKCE S256
- Dynamic Client Registration (DCR)
- Client ID Metadata Documents (CIMD), including ChatGPT's transitional singular/plural token-auth metadata
- opaque, audience-bound access and refresh tokens
- rotating refresh tokens with reuse detection
- hashed OAuth token persistence

## Required environment variables

```text
N8N_MODE=true
MCP_MODE=http
N8N_API_URL=https://your-n8n.example.com
N8N_API_KEY=<private n8n API key>
MCP_AUTH_TOKEN=<strong random value, at least 32 characters>
AUTH_TOKEN=<exactly the same value as MCP_AUTH_TOKEN>
MCP_PUBLIC_URL=https://your-mcp.example.com
MCP_OAUTH_STATE_FILE=/app/data/oauth-state.json
PORT=3000
LOG_LEVEL=info
DISABLE_CONSOLE_OUTPUT=true
NODE_ENV=production
TRUST_PROXY=1
```

Persist `/app/data`. The OAuth state file contains registered-client metadata and hashes of authorization codes and tokens; it never contains the n8n API key, the MCP authorization token, or usable OAuth bearer tokens.

During OAuth authorization, the operator enters `MCP_AUTH_TOKEN` into the authorization page hosted on their own MCP domain. The value is checked in constant time, discarded immediately, and never sent to the MCP client.

The public MCP URL is:

```text
https://your-mcp.example.com/mcp
```
