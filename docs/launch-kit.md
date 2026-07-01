# Launch Kit

Use this file when preparing the first public launch. Keep the promise narrow, concrete, and easy to verify:

> Before exposing your NAS to the internet, run one command.

## Positioning

GitHub description:

```text
AI-ready security checks for self-hosted homelabs, starting with Docker Compose.
```

Short pitch:

```text
selfhosted-doctor is a local-first security doctor for people running NAS, VPS, and homelab services with Docker Compose, reverse proxies, and Cloudflare Tunnel.
```

What makes it different:

- Built for self-hosters, not enterprise IaC teams.
- Starts from the mistakes people actually make before exposing a service: public database ports, raw Docker socket mounts, Cloudflare Tunnel without Access, hardcoded secrets, `latest` tags, missing healthchecks.
- Deterministic findings first. AI and MCP only explain or route the report.
- Local-first and read-only. It does not connect to Docker, Cloudflare, or the public internet.

## Screenshot

Primary README/social screenshot:

```text
docs/assets/readme-terminal.svg
```

Use it in posts as the visual proof that the tool is useful in 10 seconds: score, high-risk findings, exposure, and suggested fixes.

## Honest Scope

Say this clearly:

```text
v0.1 scans Docker Compose stacks, sibling .env files, and Cloudflare Tunnel config.
```

Do not imply this yet scans every NAS setup. Many NAS users run services through Synology Package Center, TrueNAS apps, Unraid templates, CasaOS, Portainer-created containers, or raw `docker run` commands. Those are good roadmap items, not launch-day promises.

Good wording:

```text
It starts with Docker Compose because that is where many self-hosted exposure mistakes are written down. Runtime inventory and NAS-native app support are next.
```

## GitHub Topics

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

## Launch Posts

Hacker News:

```text
Show HN: Selfhosted Doctor - audit Docker Compose homelabs before exposing them
```

Reddit r/selfhosted:

```text
I made a local-first security doctor for self-hosted Docker Compose stacks
```

Reddit r/homelab:

```text
Before exposing NAS services through Cloudflare Tunnel, I wanted a quick safety check
```

V2EX / Chinese title:

```text
做了一个自托管安全体检工具，给 NAS / Docker Compose / Cloudflare Tunnel 用户用
```

X / Bluesky:

```text
I built selfhosted-doctor: a local-first security check for self-hosted Docker Compose stacks.

It catches the boring-but-dangerous stuff before you expose a NAS app:
- public DB ports
- Docker socket mounts
- Cloudflare Tunnel without Access
- hardcoded secrets
- latest tags

AI/MCP-ready, but deterministic rules decide the findings.
```

## First Comment

Use this as the first comment on HN/Reddit:

```text
I built this after seeing how easy it is to expose a working self-hosted app before checking the basics.

The current version is intentionally narrow: Docker Compose + sibling .env files + Cloudflare Tunnel config. It does not call Docker, Cloudflare, or any external API.

The AI angle is the report layer: JSON/Markdown output and a read-only MCP server so tools like Claude Code/Cursor/Codex can explain findings. The scanner itself is deterministic.

I would love real-world Compose files or issues for services you want supported next.
```

## Hotspot Strategy

Good topics to ride:

- Claude Code / Cursor / Codex MCP workflows.
- Cloudflare Tunnel and Cloudflare Access discussions.
- Self-hosted incidents where an internal service was accidentally exposed.
- NAS security checklists and homelab hardening posts.
- "AI-ready but deterministic" tooling debates.

Avoid:

- Generic model-release hype with no self-hosting angle.
- Claiming the tool is an AI security scanner.
- Claiming full NAS coverage before runtime inventory exists.

## Star Funnel

The goal is not to ask for stars directly. The goal is to make people want to save it for later.

README first screen:

- One-line promise.
- Screenshot.
- One-command quickstart.
- Clear scope.

Launch post:

- Problem people recognize.
- Screenshot.
- Narrow scope.
- Ask for real-world stacks and service requests.

Issue labels to create:

- `service-rule`
- `false-positive`
- `nas-runtime`
- `cloudflare`
- `good-first-rule`
- `docs`

## 7-Day Checklist

Day 0:

- README screenshot in place.
- `npx selfhosted-doctor scan examples/vaultwarden-cloudflare` works.
- GitHub topics set.
- Issues labels created.
- One issue opened for "Runtime inventory from docker inspect / docker ps export".

Day 1:

- Launch on HN, Reddit, V2EX, and X/Bluesky.
- Reply to every serious comment within 24 hours.
- Convert repeated feedback into issues.

Day 2-3:

- Add 3-5 service rules from user requests.
- Publish a short "what it found in my homelab" post.

Day 4-7:

- Ship v0.1.1 with community-requested rules.
- Submit to relevant awesome-selfhosted / homelab lists.
- Write the roadmap issue for non-Compose NAS scanning.
