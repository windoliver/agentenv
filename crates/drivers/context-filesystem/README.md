# context-filesystem

Built-in filesystem context driver for agentenv.

Supported config:

```yaml
context:
  driver: filesystem
  mount: ~/projects/myapp
  readonly: false
  exclude:
    - ".git/"
    - "node_modules/"
```

The driver validates the mount, stores an opaque context handle, and exposes a stdio
MCP endpoint command for `agentenv-fs-mcp`. The server exposes read-only tools:
`fs_read`, `fs_grep`, `fs_list`, and `fs_search`.

Exclude patterns are intentionally simple. Values ending in `/` match path prefixes.
Other values match exact path segments or filename substrings.
