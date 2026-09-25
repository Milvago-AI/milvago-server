# Third-party dependencies

See `LICENSING.md` for this repository's own license. The dependencies below keep their
own licenses. This file lists **direct** dependencies; transitive ones are pinned in
`server/go.sum` and `console/package-lock.json`.

## Console (`console/`)

| Package | Version | License |
|---|---|---|
| react, react-dom | ^19.1.1 | MIT |
| lucide-react | 1.43.0 | ISC |
| @fontsource-variable/inter | 5.3.0 | OFL-1.1 |
| vite, vitest, jsdom, @vitejs/plugin-react | dev | MIT |
| @testing-library/react, /jest-dom, /user-event | dev | MIT |
| @types/node, @types/react, @types/react-dom | dev | MIT |
| typescript | ~5.9.2 | Apache-2.0 |

Read from each package's own metadata in `node_modules`.

## Server (`server/`)

| Module | Version | License |
|---|---|---|
| github.com/coreos/go-oidc/v3 | v3.14.1 | Apache-2.0 |
| github.com/jackc/pgx/v5 | v5.7.6 | MIT |
| github.com/prometheus/client_golang | v1.23.2 | Apache-2.0 |
| golang.org/x/crypto | v0.37.0 | BSD-3-Clause |
| golang.org/x/oauth2 | v0.30.0 | BSD-3-Clause |

## Container images

`postgres` (PostgreSQL License), `quay.io/keycloak/keycloak` (Apache-2.0),
`axllent/mailpit` (MIT), the `node` and `golang` build images, and
`gcr.io/distroless/static-debian12` (Apache-2.0) as the shipped base.

## Regenerating this list

The tables above are transcribed from upstream metadata, not from a license scanner. Before
a release, regenerate them mechanically and reconcile:

```
cd server   && go run github.com/google/go-licenses@latest report ./...
cd console  && npm ls --long --depth 0
```
