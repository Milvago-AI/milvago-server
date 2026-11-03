# Third-party dependencies

This repository (`server/` and `console/`) is licensed AGPL-3.0-only â€” see `LICENSING.md`.
Each dependency below keeps its own license. The tables list only **direct** dependencies
(what `server/go.mod` and `console/package.json` declare); transitive dependencies are
pinned in `server/go.sum` and `console/package-lock.json`.

## Server (`server/`)

Direct modules: the `require` entries in `server/go.mod` without `// indirect`.

| Module | Version | License |
|---|---|---|
| github.com/coreos/go-oidc/v3 | v3.21.0 | Apache-2.0 |
| github.com/go-jose/go-jose/v4 | v4.1.6 | Apache-2.0 |
| github.com/google/rpmpack | v0.7.1 | Apache-2.0 |
| github.com/jackc/pgx/v5 | v5.11.0 | MIT |
| github.com/tetratelabs/wazero | v1.12.0 | Apache-2.0 |
| github.com/prometheus/client_golang | v1.25.0 | Apache-2.0 |
| github.com/prometheus/client_model | v0.6.3 | Apache-2.0 |
| golang.org/x/crypto | v0.58.0 | BSD-3-Clause |
| golang.org/x/oauth2 | v0.37.0 | BSD-3-Clause |

## Console (`console/`)

Direct packages: the `dependencies` and `devDependencies` of `console/package.json`.
Versions are the exact pins declared there, as resolved in `console/package-lock.json`.

| Package | Version | License | Scope |
|---|---|---|---|
| react | 19.3.1 | MIT | runtime |
| react-dom | 19.3.1 | MIT | runtime |
| lucide-react | 1.62.0 | ISC | runtime |
| @fontsource-variable/inter | 5.3.0 | OFL-1.1 | runtime |
| @testing-library/jest-dom | 7.0.1 | MIT | dev |
| @testing-library/react | 16.3.3 | MIT | dev |
| @testing-library/user-event | 14.6.8 | MIT | dev |
| @types/node | 26.6.5 | MIT | dev |
| @types/react | 19.3.0 | MIT | dev |
| @types/react-dom | 19.3.0 | MIT | dev |
| @vitejs/plugin-react | 6.1.2 | MIT | dev |
| @vitest/coverage-v8 | 5.0.5 | MIT | dev |
| jsdom | 30.1.3 | MIT | dev |
| typescript | 7.0.2 | Apache-2.0 | dev |
| vite | 8.3.5 | MIT | dev |
| vitest | 5.0.5 | MIT | dev |

## Shared DLP engine (`dlp-engine/`)

The Apache-2.0 engine is compiled to WASM and embedded in the Go server and served
to the local browser laboratory. Its direct dependencies retain their licenses:

| Crate | Version | License |
|---|---|---|
| regex | 1.13.1 | MIT OR Apache-2.0 |
| serde | 1.0.229 | MIT OR Apache-2.0 |
| serde_json | 1.0.154 | MIT OR Apache-2.0 |
| unicode-normalization | 0.1.25 | MIT OR Apache-2.0 |
| unicode-security | 0.1.2 | MIT OR Apache-2.0 |

Transitive versions are pinned in `dlp-engine/Cargo.lock`.

## Container images

Images referenced by `compose.yaml` and `install-private.sh` (compose services), and
by `deploy/Dockerfile` (build stages and the shipped base).

| Image | Tag | License | Role |
|---|---|---|---|
| postgres | 18.4 | PostgreSQL License | compose service (database) |
| axllent/mailpit | v1.32.0 | MIT | compose service (mail) |
| quay.io/keycloak/keycloak | 26.8.1 | Apache-2.0 | compose service (identity) |
| caddy | 2.11.4-alpine | Apache-2.0 | private installer gateway (pinned by digest) |
| node | 26.13.0-trixie-slim | MIT | build stage (console) |
| rust | 1.96.1-trixie | MIT OR Apache-2.0 | build stage (DLP) |
| golang | 1.27.3-trixie | BSD-3-Clause | build stage (server) |
| gcr.io/distroless/static-debian13 | nonroot | Apache-2.0 | shipped base |

## Regenerating this list

Server table â€” read the LICENSE file for each direct module (the `require` entries in
`server/go.mod` without `// indirect`) from the Go module cache:

```
go env GOMODCACHE
cat "$(go env GOMODCACHE)/<module>@<version>/LICENSE"
```

Cross-checked with a pinned license scanner (exact version, never `@latest`), from `server/`:

```
go run github.com/google/go-licenses@v1.6.0 report ./...
```

Console table â€” for each key of `dependencies` and `devDependencies` in
`console/package.json`, read `.version` and `.license` from
`packages["node_modules/<name>"]` in `console/package-lock.json`.

Container images table â€” read the `image:` values in `compose.yaml` and the `FROM` lines
of `deploy/Dockerfile`, then look up each image's license.

Updated on 2026-11-02 from `server/go.mod`, `console/package-lock.json`, `compose.yaml`,
`install-private.sh` and `deploy/Dockerfile`.

## Discovery engine and catalogue

`discovery-engine/` is separately licensed Apache-2.0, including the native/WASM
engine and reviewed catalogue adaptation. See `discovery-engine/LICENSE` and
`discovery-engine/NOTICE` for Julius (Praetorian) OpenClaw probe attribution and
the separately reviewed Hermes contribution ed26a485 (pull request 151).
Its direct crates are regex 1.13.1, serde 1.0.229 and serde_json 1.0.154
(MIT OR Apache-2.0); transitive versions are pinned in its Cargo.lock.

The server YAML parser is go.yaml.in/yaml/v3 v3.0.5 (MIT for the libyaml-ported
files, Apache-2.0 for the remaining files). The upstream notices and full Apache
terms are retained in `licenses/`. Shipped server images retain these notices
under `/licenses/`, alongside the engine notice and license.
