# context-mcp-generic

Built-in context driver for existing MCP HTTP endpoints.

Supported config:

```yaml
context:
  driver: mcp-generic
  endpoint:
    url: https://mcp.example.com/sse
    transport: http+sse
  credentials:
    MCP_TOKEN:
      source: env
```

The driver validates outbound endpoint URLs through the shared SSRF validator,
declares an optional `MCP_TOKEN` credential name, returns one network allow rule
for the endpoint host, and never stores credential values.
