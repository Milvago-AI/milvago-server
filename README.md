<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/milvago-logo-inverse.svg">
    <img src=".github/assets/milvago-logo.svg" alt="Milvago" height="64">
  </picture>
</p>

<h3 align="center">See the AI your organization actually uses.</h3>

<p align="center">
  Open source Shadow AI governance, from the browser where it happens.<br>
  Discover every AI platform your people reach, see what leaves the machine, and mask it before it does.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: AGPL-3.0-only" src="https://img.shields.io/badge/license-AGPL--3.0--only-18181B"></a>
  <img alt="Go 1.27" src="https://img.shields.io/badge/Go-1.27-00ADD8">
  <img alt="React 19" src="https://img.shields.io/badge/React-19-149ECA">
  <img alt="Distroless image" src="https://img.shields.io/badge/image-distroless%2C%20non--root-18181B">
  <img alt="Languages" src="https://img.shields.io/badge/UI-EN%20%C2%B7%20FR%20%C2%B7%20ES%20%C2%B7%20PT--BR-18181B">
  <a href="https://discord.gg/69JPyVjqv"><img alt="Discord" src="https://img.shields.io/badge/Discord-join%20the%20community-5865F2?logo=discord&logoColor=white"></a>
</p>

---

## Why Milvago

Your people already use generative AI. Some of it is sanctioned; most of it is a browser tab
nobody inventoried. A policy nobody can observe is a wish, and blocking everything only moves
the problem to personal devices.

Milvago gives you the missing layer: **an accurate inventory of AI usage, and control at the
point where data actually leaves**, without reading more than you need and without turning
your security team into a surveillance desk.

## What you get

### Discover

- **169 known AI platforms detected by presence.** The browser endpoint reports that a host
  was reached, and nothing of the page. You find out which assistants are in use before
  deciding anything.
- **Mute what you officially use.** Hide sanctioned platforms from Discovery without touching
  detection: visits keep being recorded, the noise goes away.

### Understand

- **Conversations on ChatGPT and Claude**: prompts, responses, and which model answered.
- **Cartography**: a flow diagram of who uses which tool, on which provider, with which model.
- **Reports**: aggregated views, CSV and JSON export, and a printable synthesis for the
  steering committee.

### Protect

- **Mask before it leaves.** Custom masking rules (RE2, up to 25 per organization) replace
  sensitive values in the prompt itself with readable markers such as `[IP]`, or `[IP1]` and
  `[IP2]` when there are several.
- **Block file uploads** to covered assistants, on the upload routes measured on each site,
  never on a guess.

### Built for privacy

- Content, device names and identities **encrypted at rest**.
- **Pseudonymous by default**: people appear as aliases. Revealing an identity takes a
  dedicated permission, a fresh second factor and a written reason; it is audited and expires
  after 15 minutes.
- Content retention from **1 to 30 days**, owner-only purge behind a fresh second factor, and
  an **aggregate-only** mode that keeps counts and drops the rest.

### Secure by default

- Sign-in through **OpenID Connect** (Keycloak included), **TOTP** second factor.
- **Role-based access** with four built-in roles (owner, admin, viewer, reporter) and a full
  **audit log**.
- **REST API** with scoped keys (`mvk_…`): a key never exceeds its creator's *current* rights.
- A one-time **setup token** opens the first-run wizard, then closes it for good. HTTPS is
  required beyond localhost.
- Shipped as a **distroless, non-root** container: no shell, no package manager.

## How it works

```
  Browser + Milvago extension          Milvago server (Go)              Console (React)
 ┌──────────────────────────┐   HTTPS  ┌──────────────────────┐        ┌─────────────────┐
 │ presence · capture ·     │ ───────► │ policy · ingestion · │ ◄───── │ discovery · map │
 │ masking · upload guard   │ ◄─────── │ signed catalogue     │        │ reports · admin │
 └──────────────────────────┘  policy  └──────────┬───────────┘        └─────────────────┘
                                                  │
                                    PostgreSQL ◄──┴──► Keycloak (OIDC)
```

The server signs the detection catalogue and the policy it hands to endpoints; endpoints
enforce it locally, so masking happens **before** the request reaches the AI provider.

This repository holds the **server and the console**. The endpoint agent and its browser
extension are distributed separately.

## Quick start

Requirements: Docker with Compose v2, and Node.js 22 for the initialization script.

```bash
node scripts/local-init.mjs     # fresh .env and identity realm, random secrets
docker compose up -d --build    # PostgreSQL, Keycloak, Mailpit and Milvago
```

Open **http://localhost:4020**, enter the `MILVAGO_SETUP_TOKEN` from `.env`, and the wizard
walks you through the first administrator, second factor, organization, mail server and
privacy defaults. Details in [INSTALL.md](INSTALL.md). To use the currently private GHCR image instead of
building from source, copy `install-private.sh` to a Linux host and run it from any
directory. It fetches a pinned Community checkout when needed and installs missing
Docker packages through the supported distribution's package manager. A standalone
install needs access to the private repository and package, with a classic GitHub
token scoped to `repo` and `read:packages`.

## Community and Enterprise

Community is free, open source and complete for a single organization. Without a licence it
runs with 5 devices and a single owner; a **free Community licence**, requested from the setup
wizard, lifts those limits and unlocks custom roles, member invitations, SSO and LDAP.

| | Community | Enterprise |
|---|---|---|
| Organizations | One | Many, isolated by PostgreSQL row-level security |
| Endpoints | Browser | Browser and native AI tools (Claude Code, Codex, Claude Desktop) |
| Conversation capture | ChatGPT, Claude | Nine providers |
| Presence detection | 169 platforms | 169 platforms |
| Masking | Custom rules | Custom rules and built-in sensitive-data patterns |
| Model control and usage sensitivity | — | ✓ |
| MCP server, observability export (OTLP) | — | ✓ |
| License | AGPL-3.0-only | Commercial |

Enterprise is available from Milvago AI, LLC — [www.milvago.ai](https://www.milvago.ai).

## Repository layout

| Path | What it is |
|---|---|
| `server/` | Go backend, migrations, signed detection catalogue |
| `console/` | React console (Vite, TypeScript), four languages |
| `deploy/` | Container build, PostgreSQL initialization, identity theme |

Run the suites with `cd console && npm ci && npm test` and `cd server && go test ./...`.
`docker compose build` runs both inside the build: an image is never produced from a red tree.

## Community

Questions, ideas, setups to share: join the **[Milvago AI Discord](https://discord.gg/69JPyVjqv)**.
Bugs and feature requests go to [GitHub issues](https://github.com/Milvago-AI/milvago-server/issues);
[SUPPORT.md](SUPPORT.md) says which channel fits what. Everyone taking part follows the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Found a vulnerability? Please do not open a public issue — see [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first, and see
[CHANGELOG.md](CHANGELOG.md) for what changed between releases.

## License

Copyright © 2026 Milvago AI, LLC. The server and the console are licensed under
[AGPL-3.0-only](LICENSE); see [LICENSING.md](LICENSING.md) for what that means for
operators, and [THIRD-PARTY.md](THIRD-PARTY.md) for dependencies. "Milvago" and the Milvago
logo are trademarks of Milvago AI, LLC.
