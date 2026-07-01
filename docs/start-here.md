# Start Here

This repository is a product experiment: build a useful open-source tool that helps self-hosted users audit their homelab setup before exposing services to the internet.

## Positioning

`selfhosted-doctor` is:

> AI-ready security checks for self-hosted homelabs, starting with Docker Compose.

The first version should be small, local-first, and useful without AI.

## Product Discipline

For v0.1:

- Do not build a Web UI.
- Do not auto-fix user files.
- Do not connect to the Docker daemon.
- Do not call the Cloudflare API.
- Do not use an LLM as the source of truth for security findings.
- Do generate reports that AI coding tools can read.

## Recommended Next Step

Ask Claude Code to build the MVP from `docs/claude-code-prompt.md`.

The first useful slice is:

```text
CLI scan + JSON report + Markdown report + 3 examples + tests
```

Add MCP and AI explanation after the scanner core works.
