# selfhosted-doctor

AI-ready security checks for self-hosted homelabs, starting with Docker Compose.

> Before exposing your NAS to the internet, run one command.

`selfhosted-doctor` is a local-first security doctor for people who run services on a NAS, VPS, or homelab with Docker Compose, reverse proxies, and Cloudflare Tunnel.

The goal is not to replace Trivy, Checkov, or enterprise security scanners. The goal is to catch the common self-hosted mistakes that happen right before a private service becomes public.

## Planned Quickstart

```bash
npx selfhosted-doctor scan docker-compose.yml
```

Example output:

```text
selfhosted-doctor report

Risk score: 72/100

High
- vaultwarden exposes 8080 on 0.0.0.0
- .env contains possible SMTP password
- postgres is mapped to a host port

Medium
- immich has no healthcheck
- cloudflared tunnel has no Access policy hint
- postgres image is not pinned

Exposure
- vaultwarden: 0.0.0.0:8080 -> container:80
- jellyfin: 8096 -> container:8096
```

## What It Will Check First

- Publicly exposed ports in Docker Compose
- `privileged: true` and `network_mode: host`
- Docker socket mounts
- Exposed database ports such as Postgres, MySQL, Redis, and MongoDB
- Plaintext secrets in Compose and `.env`-style files
- `latest` image tags and unpinned images
- Missing `healthcheck` and restart policy
- Service-specific notes for Vaultwarden, Immich, Nextcloud, Jellyfin, Home Assistant, Gitea, and common reverse proxies
- Cloudflare Tunnel exposure hints

## AI And MCP

The scanner should be useful without AI. AI is an optional explanation layer.

Planned AI-friendly features:

- Generate a JSON report that Claude Code, Codex, Cursor, and other agents can read
- Provide a read-only MCP server for local Compose security inspection
- Explain findings in plain language using the user's chosen provider
- Redact secrets before producing reports or sending anything to an AI provider

The LLM will not be the source of truth for security findings. Deterministic rules come first; AI explains the result.

## MVP Scope

The first version focuses on:

```text
Docker Compose file -> deterministic scan -> terminal / JSON / Markdown report
```

Out of scope for v0.1:

- No automatic fixes
- No Docker daemon access
- No Cloudflare API calls
- No public internet scanning
- No Web UI

## Status

This repository is being bootstrapped. The product brief, MVP spec, and launch plan live in `docs/` while the first implementation is being built.

## Disclaimer

`selfhosted-doctor` is a best-effort configuration checker, not a security guarantee. Always review findings manually before exposing services to the internet.

## License

MIT
