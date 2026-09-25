# Third-party dependencies

This repository (`server/` and `console/`) is licensed AGPL-3.0-only — see `LICENSING.md`.
Each dependency below keeps its own license. The tables list only **direct** dependencies
(what `server/go.mod` and `console/package.json` declare); transitive dependencies are
pinned in `server/go.sum` and `console/package-lock.json`.

## Server (`server/`)

Direct modules: the `require` entries in `server/go.mod` without `// indirect`.

| Module | Version | License |
|---|---|---|
| github.com/coreos/go-oidc/v3 | v3.15.0 | Apache-2.0 |
| github.com/go-jose/go-jose/v4 | v4.1.4 | Apache-2.0 |
| github.com/google/rpmpack | v0.7.1 | Apache-2.0 |
| github.com/jackc/pgx/v5 | v5.9.2 | MIT |
| github.com/prometheus/client_golang | v1.23.2 | Apache-2.0 |
| github.com/prometheus/client_model | v0.6.2 | Apache-2.0 |
| golang.org/x/crypto | v0.56.0 | BSD-3-Clause |
| golang.org/x/oauth2 | v0.30.0 | BSD-3-Clause |

## Console (`console/`)

Direct packages: the `dependencies` and `devDependencies` of `console/package.json`.
Versions are the exact pins declared there, as resolved in `console/package-lock.json`.

| Package | Version | License | Scope |
|---|---|---|---|
| react | 19.2.8 | MIT | runtime |
| react-dom | 19.2.8 | MIT | runtime |
| lucide-react | 1.43.0 | ISC | runtime |
| @fontsource-variable/inter | 5.3.0 | OFL-1.1 | runtime |
| @testing-library/jest-dom | 6.9.1 | MIT | dev |
| @testing-library/react | 16.3.3 | MIT | dev |
| @testing-library/user-event | 14.6.7 | MIT | dev |
| @types/node | 22.20.1 | MIT | dev |
| @types/react | 19.2.18 | MIT | dev |
| @types/react-dom | 19.2.7 | MIT | dev |
| @vitejs/plugin-react | 4.7.0 | MIT | dev |
| @vitest/coverage-v8 | 3.2.7 | MIT | dev |
| jsdom | 26.1.0 | MIT | dev |
| typescript | 5.9.3 | Apache-2.0 | dev |
| vite | 7.3.6 | MIT | dev |
| vitest | 3.2.7 | MIT | dev |

## Container images

Images referenced by `compose.yaml` (compose services) and by `deploy/Dockerfile` (build
stages and the shipped base).

| Image | Tag | License | Role |
|---|---|---|---|
| postgres | 18.3 | PostgreSQL License | compose service (database) |
| axllent/mailpit | v1.20.3 | MIT | compose service (mail) |
| quay.io/keycloak/keycloak | 26.7.4 | Apache-2.0 | compose service (identity) |
| node | 22.23.2-bookworm-slim | MIT | build stage (console) |
| golang | 1.27.1-bookworm | BSD-3-Clause | build stage (server) |
| gcr.io/distroless/static-debian12 | nonroot | Apache-2.0 | shipped base |

## Regenerating this list

Server table — read the LICENSE file for each direct module (the `require` entries in
`server/go.mod` without `// indirect`) from the Go module cache:

```
go env GOMODCACHE
cat "$(go env GOMODCACHE)/<module>@<version>/LICENSE"
```

Cross-checked with a pinned license scanner (exact version, never `@latest`), from `server/`:

```
go run github.com/google/go-licenses@v1.6.0 report ./...
```

Console table — for each key of `dependencies` and `devDependencies` in
`console/package.json`, read `.version` and `.license` from
`packages["node_modules/<name>"]` in `console/package-lock.json`.

Container images table — read the `image:` values in `compose.yaml` and the `FROM` lines
of `deploy/Dockerfile`, then look up each image's license.

Generated on 2026-09-25 from `server/go.mod`, `console/package-lock.json`, `compose.yaml`
and `deploy/Dockerfile`.
