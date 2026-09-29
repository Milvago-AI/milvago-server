# Contributing

Thanks for helping. Before a large change, say hello on the
[Milvago AI Discord](https://discord.gg/69JPyVjqv) or open an issue: agreeing on the approach
first saves everyone a rewrite. Everyone taking part follows the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Licensing of contributions

A contribution is accepted under the license of the component it touches —
AGPL-3.0-only for `server/` and `console/` (see `LICENSING.md`). Copyright holder:
Milvago AI, LLC. Inbound equals outbound:
we ask for no copyright assignment.

Sign your commits off (`git commit -s`), which states that you have the right to submit the
work under that license — the [Developer Certificate of Origin](https://developercertificate.org/).

## Before opening a pull request

The repositories are private and use GitHub Free. Development work is pushed to `dev`. Open a
pull request from `dev` to `main` only after CI is green; a maintainer must explicitly approve
the merge. GitHub Free cannot enforce branch protections for private repositories, so this is a
review procedure. Contributors without write access cannot push branches to these repositories.


Run what your change touches:

```
cd console && npm ci && npm test
cd server && go test ./...
```

A pull request that changes behavior comes with a test that fails without it. A test whose
only proof is a zero exit code proves nothing: assert on what the code actually produced.

## Editing conventions

- The codebase explains *why* in comments and keeps *what* in the code. A comment that
  restates the line above it is noise; a comment that records the reason a simpler approach
  was rejected is what a reader needs six months later.
- Visible strings live in the catalogues under `console/src/locales/` — four languages, the
  English file being the source of keys. A string hardcoded in JSX will fail review.
- No real names, customer names or credentials anywhere: code, tests, fixtures, comments.
- Keep changes scoped. A formatting sweep mixed into a behavior change costs more to review
  than both apart.

## Reporting bugs

Open an issue with the version or commit, what you did, what happened and what you expected.
For anything with a security dimension, follow `SECURITY.md` instead — not the issue tracker.

## Release channels

The release pipeline is prepared but has not published `v1.0.0`. A release from `main` publishes
the anonymous public image `ghcr.io/milvago-ai/milvago-server:1.0.0`, pinned to its immutable
digest and signed with cosign. It never publishes `latest`. Builds from `dev` use the separate
private package `ghcr.io/milvago-ai/milvago-server-dev:sha-<full-commit>`.
