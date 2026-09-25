# Running Milvago Community locally

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

Nothing here is a default credential: a second run preserves what exists rather than
regenerating it, so restarting never invalidates sessions or sealed content.

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

**Beyond localhost, HTTPS is required.** The server refuses a cleartext `APP_URL` anywhere
but loopback, and the session cookie carries `Secure` as soon as the scheme is `https`. An
instance served over plain HTTP on a real hostname will load the console and refuse every
sign-in — by design, not by misconfiguration.

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
