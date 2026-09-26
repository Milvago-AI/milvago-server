# Running Milvago Community locally

## Install the private GHCR image

Copy `install-private.sh` to a Linux host and run it from any directory:

```bash
bash install-private.sh
```

When no complete checkout is present, the script downloads the pinned private Community
server source into `$HOME/milvago-community`. Set `MILVAGO_DIR` to another absolute
path if needed. A standalone install needs a GitHub personal access token (classic)
with `repo` and `read:packages`, plus access to the private repository and package.
From a complete checkout, only `read:packages` is needed. Each run selects the latest
published Community image, verifies its signature and replaces the application container
when it changes. The checkout, local configuration and database are preserved. The GitHub
token is never stored there.
The pinned Node container downloads and extracts the source; no host `tar` is needed.
When Docker is already working, no host `curl` or `wget` is needed either.

On Linux, the script installs missing Docker Engine and incompatible or missing Compose packages through Docker's
official `apt` repository on Ubuntu/Debian or `dnf` repositories on Fedora and RHEL-compatible releases 8–10 (RHEL, CentOS, Rocky Linux, AlmaLinux, Oracle Linux, and derivatives declaring `ID_LIKE=rhel` or `centos`). EL8 uses Docker's RHEL 8 repository; EL9 and EL10 derivatives use Docker's CentOS repository. The package manager selects the available Docker Engine, CLI, containerd.io and Compose versions from that repository. Existing working Docker installations are left in place. Package installation requires root or `sudo`, plus `curl` or
`wget` and `sha256sum`. Other distributions need Docker Engine and Compose installed first.
The script keeps Docker's registry credentials in a temporary directory. It verifies
the pinned image signature with `cosign.pub`, generates `.env` and the identity realm using a
pinned Node container when needed, then starts PostgreSQL, Keycloak, Mailpit, the
Community server and Caddy. The token is never written to the repository. A later run preserves the
local configuration and database.

The image contains the server and console only. It does not serve an agent, browser
extension or installer. The script detects a private IPv4 address (or accepts
`MILVAGO_HOST_IP`), binds Caddy to port 4020 on that address, and prints
the console URL and the path to the owner-readable `.env` file at the end.
Caddy forwards `/realms`, `/admin`, `/resources` and `/js` to Keycloak; the
application and Keycloak have no direct host port in this installation. Only
TCP port 4020 is needed through the host firewall. No secret value is printed.
Database and Mailpit ports remain on loopback. The installer waits for
`/readyz` through the published Caddy port before reporting success; if the
gateway fails, it prints its recent logs.
HTTP on a LAN is intended for trusted test networks; use an HTTPS reverse
proxy or gateway for broader access.

## Build from source

## Requirements

- Docker with Compose v2
- Node.js 22 (for the local initialization script)
- Go 1.27.1 only if you want to run the server suite outside the containers

## 1. Generate a local configuration

```
node scripts/local-init.mjs
```

It writes, once and only if they are absent:

- `.env` — database, identity and cryptographic secrets, all randomly generated
- `.local/generated/realm.json` — the identity realm to import, with no user account in it
- `MILVAGO_SETUP_TOKEN` in `.env` — the one-time token that opens the setup wizard

The Keycloak bootstrap username is `bootstrap-admin`; its
`IDENTITY_ADMIN_PASSWORD` is generated from 32 random bytes. `SESSION_KEY` and
`CONTENT_KEYS` are separate random encryption roots. This stack has no
`ENCRYPTION_KEY` setting. Read their values and `MILVAGO_SETUP_TOKEN` only in the
owner-readable `.env` file.

A second run preserves these values rather than regenerating them, so restarting
never invalidates sessions or sealed content.

## 2. Start the stack

```
docker compose up -d --build
```

| Service | Address | Role |
|---|---|---|
| `application` | http://localhost:4020 | Server and console |
| `identity` | http://localhost:4080 | Keycloak, realm `milvago` |
| `mail` | http://localhost:4081 | Mailpit, catches outgoing mail |
| `database` | 127.0.0.1:55432 | PostgreSQL |

Every port is bound to the loopback interface.

## 3. Create the first administrator

Open http://localhost:4020: with no administrator yet, the console shows the setup wizard
instead of the sign-in page. Enter the `MILVAGO_SETUP_TOKEN` value from `.env`, then choose
the administrator account and its password, the second factor, the organization, the e-mail
server (Mailpit answers on host `mail`, port `1025`, no security) and the privacy defaults.
Nothing is saved before the last step. You then sign in with the account you chose, which
becomes the owner. Once an administrator exists the wizard is closed for good and the token
opens nothing; you may remove it from `.env`.

HTTP origins are accepted for testing over a trusted LAN. Use HTTPS through a reverse
proxy or gateway for broader access; session cookies carry `Secure` when the external
application URL uses HTTPS.

## Endpoint agent and browser extension

They live in their own repository. The image built here serves no extension (`/ext/*`
answers `503 extension_unconfigured`) and no installer.

## Running the tests

```
cd console && npm ci && npm test        # console
cd server && go test ./...              # server, Community edition
```

`docker compose build` runs the console and server suites inside the build itself: an image
is not produced from a red tree.
