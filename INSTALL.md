# Running Milvago Community locally

## Install the prepared release

The repository copy of `install-private.sh` is a non-executable template. Download the installer,
its checksum file, and its immutable release description anonymously from the public `v1.0.0`
release:

```bash
mkdir milvago-install && cd milvago-install
release_url=https://github.com/Milvago-AI/milvago-server/releases/download/v1.0.0
curl -fLO "$release_url/install-private.sh"
curl -fLO "$release_url/SHA256SUMS"
curl -fLO "$release_url/release.json"
sha256sum --check SHA256SUMS
bash install-private.sh
```

`wget` can replace each `curl -fLO` command. No GitHub CLI login, GitHub token, or registry
credential is required. The server image is pulled anonymously from
`ghcr.io/milvago-ai/milvago-server:1.0.0` using the exact digest recorded in `release.json`.

The release pipeline generates `install-private.sh`, `SHA256SUMS`, and `release.json` together.
They bind the server version, full commit, image digest, and cosign signature verification to
that release. `MILVAGO_VERSION`, when set, must equal `1.0.0`; the installer rejects a different
or floating value. It never uses `latest`.

On a first standalone installation only, the installer obtains the public server source pinned to
the release commit and places it in `$HOME/milvago-community`. Set `MILVAGO_DIR` to another absolute
path if needed. It does not synchronize an existing checkout. Every run preserves local
configuration and the database while replacing the application container only when the pinned
image changes.

Before detecting a host address or beginning installation, the script checks the core utilities,
`tar`, `gzip`, a CA certificate bundle, and either `curl` or `wget`; it keeps an existing `wget`.
When neither `ip` nor `hostname` is available and `MILVAGO_HOST_IP` is unset, it also needs the IP
utility. On Debian and Ubuntu, missing prerequisites are installed with `apt-get`; on RPM-family
systems, the script uses `dnf` or `yum`. It resolves an exact candidate version for every missing
package before the transaction, installs only those packages without a system-wide upgrade, and
verifies the tools after installation. Root or `sudo` is required only when packages are missing.

The script installs missing Docker Engine and incompatible or missing Compose packages through
Docker's official package repositories only on supported Ubuntu, Debian, Fedora, RHEL 8–10, and
their supported derivatives. Existing working Docker installations are left in place. Other Linux
distributions can run the installer when Docker, Compose, and the prerequisites already exist. If
missing prerequisites require an unsupported package manager, the installer stops with a clear
error; it does not claim support for every distribution or version.

The base image contains the server and console only. The installer also downloads the pinned
Community `0.6.4` Windows and Linux agent bundle anonymously from its public release, verifies its
SHA-256, Ed25519 signatures, and manifest expiration (the prepared manifests are valid through 2027-09-29), then mounts the verified files read-only so the console can provide
agent downloads. Version `0.6.4` is shared by the agent and browser extension in both editions.
The console delivers one Windows ZIP containing the immutable MSI, its matching script, an
organization provisioning JSON and an installation `README.md`. The Windows MSI has no
Authenticode publisher signature yet. The base image does not host a browser extension. Before a
first installation, the script asks for the exact public HTTP or HTTPS origin where users will open
Milvago, for example `https://console.example.test`. It never guesses a LAN address. The value must
be an origin only: no path, query, or fragment. For unattended installation, set
`MILVAGO_PUBLIC_URL=https://console.example.test`; this skips the prompt. The script binds Caddy to
port 4020 and prints the selected URL and the path to the owner-readable `.env` file at the end.
Caddy forwards the public realm, resources and JavaScript assets to Keycloak. It returns 404 for
`/admin` and `/realms/master`; the Keycloak administrator API is reachable only from the internal
container network. The application and Keycloak have no direct host port in this installation.
Only TCP port 4020 is needed through the host firewall. No secret value is printed. Database and
Mailpit ports remain on loopback. The installer waits for `/readyz` through the published Caddy
port before reporting success; if the gateway fails, it prints its recent logs.

HTTP on a LAN is intended for trusted test networks; use an HTTPS reverse proxy or gateway for
broader access. The front proxy must preserve the Host header and send `X-Forwarded-Proto: https`.
On a later run, a public URL already confirmed in the database is preserved. If the supplied or
entered URL conflicts with it, the installer stops. Change the URL in **Administration > Settings**;
this updates the console redirect and Keycloak through its private API. Already enrolled agents
retain their prior URL and must be re-enrolled to move.

If the final setup-wizard step returns `502` after an installation made with an earlier installer, rerun the current installer with the same public URL. It repairs the four required Keycloak service-account roles: `manage-clients`, `view-clients`, `manage-identity-providers`, and `view-identity-providers`; it does not grant `realm-admin`. The rerun preserves the database and existing accounts. A `502` can have other causes, so inspect the application and gateway logs when it persists after the rerun.

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

They live in their own repository. An image built from this source alone serves no extension (`/ext/*` answers `503 extension_unconfigured`) and no installer. The prepared installation script fetches and mounts the signed Community agent bundle separately.

## Running the tests

```
cd console && npm ci && npm test        # console
cd server && go test ./...              # server, Community edition
```

`docker compose build` runs the console and server suites inside the build itself: an image
is not produced from a red tree.
