# Headless CI Example

This template runs Codex in non-interactive mode for repository maintenance jobs such as lint fixes.

## Prerequisites

```sh
export OPENAI_API_KEY=sk-openai-example
```

## CI Flow

```sh
agentenv create ci-fix --non-interactive
agentenv exec ci-fix -- sh -lc 'echo ok'
agentenv freeze ci-fix --output agentenv.lock
agentenv destroy ci-fix --yes --non-interactive
```

Use your CI system to run project-specific commands inside `agentenv exec`, then inspect the working tree before committing changes.
