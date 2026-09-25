# Changelog

All notable changes to this repository are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

First public release of the Milvago Community server and console.

### Added

- Presence detection of 169 known AI platforms from the signed detection catalogue, with a
  per-platform mute for sanctioned tools.
- Conversation capture on ChatGPT and Claude, cartography of tools, providers and models,
  reports with CSV and JSON export.
- Custom masking rules and upload blocking on measured routes, enforced by the endpoint.
- Content and identities encrypted at rest, pseudonymous users, audited and time-limited
  identity reveal, bounded retention and purge.
- OpenID Connect sign-in, TOTP second factor, four built-in roles, audit log, scoped API keys.
- First-run setup wizard, free Community licence request.
- English as the default language; French, Spanish and Brazilian Portuguese available.

### Security

- File access to the extension, release and installer directories confined with `os.Root`.
- Second-factor redirect limited to a same-origin path.
- CI checkouts no longer persist credentials; actions pinned by digest.
