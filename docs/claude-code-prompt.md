# Claude Code Prompt

Use this prompt to start implementation work.

```text
We are building an open-source project named `selfhosted-doctor`.

Product goal:
Build a useful, local-first security doctor for self-hosted / NAS / homelab users.
The first version starts with Docker Compose because that is the most common input these users already have.

Core promise:
"Before exposing your NAS to the internet, run one command."

User story:
As a self-hosted user, I want to point a tool at my Docker Compose setup and get a clear report telling me what might be risky before I expose services through Cloudflare Tunnel, a reverse proxy, or public ports.

MVP outcome:
- A CLI that can scan a Compose file or a directory of Compose files.
- A deterministic scanner that catches high-value homelab risks.
- Terminal, JSON, and Markdown reports.
- A few realistic examples that make the project easy to understand.
- A test suite for the scanner behavior.
- An AI-ready shape: reports should be easy for Claude Code / Codex / Cursor to read.

Risks worth detecting in the first version:
- Publicly exposed ports.
- Privileged containers.
- Host network mode.
- Docker socket mounts.
- Exposed database ports.
- Plaintext secrets in Compose or `.env`-style files.
- Weak image hygiene such as `latest` tags.
- Missing healthchecks or restart policies.
- Service-specific risks for common apps such as Vaultwarden, Immich, Nextcloud, Jellyfin, Home Assistant, Gitea, databases, reverse proxies, and Cloudflare Tunnel.

Product constraints:
- Do not auto-fix files in MVP.
- Do not connect to Docker daemon.
- Do not call Cloudflare API.
- Do not leak secret values in reports.
- Do not make LLM output the source of truth for security findings.
- Deterministic scanner first, AI explanation second.

AI/MCP direction:
Add a lightweight read-only MCP server or AI explanation skeleton only if it does not distract from the core scanner. AI should explain findings, not invent them.

Engineering guidance:
Choose the language, libraries, and directory structure that make the MVP simple, maintainable, and easy to publish. TypeScript/npm is a good default because `npx selfhosted-doctor` is a strong distribution path and MCP support is mature, but use your judgment if another approach is clearly better.

Deliverables:
1. A working first implementation.
2. A short implementation plan before coding.
3. Clear README updates if the actual usage differs from the current planned usage.
4. Tests and examples that prove the scanner works.
5. Notes on tradeoffs, known gaps, and what should come next.

Please inspect the repo first, decide the best minimal architecture, briefly explain your plan, then implement. Prefer a small sharp MVP over a broad unfinished tool.
```
