# Launch Plan

For copy/paste launch assets, use [`docs/launch-kit.md`](launch-kit.md).

## Launch Principle

Do not launch a big vague tool. Launch a small memorable check:

> Before exposing your NAS to the internet, run one command.

AI/MCP is the hook, but deterministic scanning is the product.

## Launch Assets

Before public launch, prepare:

- README with one-command quickstart
- Terminal report screenshot (`docs/assets/readme-terminal.svg`)
- Three example stacks:
  - Vaultwarden + Cloudflare Tunnel
  - Immich + Postgres
  - Nextcloud + database
- A short demo GIF or screenshot thread
- Clear disclaimer that the tool is local-first and best-effort

## GitHub Topics

Use:

```text
self-hosted
homelab
nas
docker-compose
security
cloudflare-tunnel
mcp
ai-tools
claude-code
codex
devops
```

## Launch Channels

Hacker News:

```text
Show HN: Selfhosted Doctor - audit Docker Compose homelabs before exposing them
```

Reddit r/selfhosted:

```text
I made a Docker Compose security doctor for self-hosted homelabs
```

Reddit r/homelab:

```text
Before exposing NAS services through Cloudflare Tunnel, I wanted a quick safety check
```

Chinese channels:

```text
做了一个自托管安全体检工具，给 NAS / Docker Compose / Cloudflare Tunnel 用户用
```

## Hot Topics To Follow

Good fits:

- MCP security discussions
- Claude Code / Codex / Cursor MCP support
- Cloudflare Tunnel and Cloudflare Access updates
- Self-hosted service security incidents
- Docker Compose security best practices
- NAS users asking how to audit services before exposing them

Avoid:

- Generic model launches
- Unrelated AI agent hype
- Topics that do not connect to self-hosting, security, or local infrastructure
- Claiming full NAS support before non-Compose runtime inventory exists

## 30-Day Plan

Week 1:

- MVP CLI
- 3 examples
- README
- Tests

Week 2:

- MCP server
- AI explain provider interface
- Launch on HN, Reddit, X, V2EX
- Collect issues

Week 3:

- More service rules
- Better report screenshots
- Chinese tutorial
- Submit to awesome lists

Week 4:

- Better Cloudflare Tunnel scanning
- Mermaid exposure map
- v0.2 release
- Retrospective post

## Star Targets

Conservative:

- 50 stars in 7 days
- 200 stars in 30 days

Good:

- 100 stars in 7 days
- 500 stars in 30 days

Breakout:

- HN front page or a Reddit hit
- 500+ stars in 7 days
