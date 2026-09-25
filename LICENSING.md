# Licensing

**Copyright (c) 2026 Milvago AI, LLC.** Milvago AI, LLC is the copyright holder and the
licensor of every component in this repository.

| Component | Path | License |
| --- | --- | --- |
| Backend, single organization | `server/` | AGPL-3.0-only |
| Console frontend | `console/` | AGPL-3.0-only |

Full text: `LICENSE`. Where a directory carries its own license file (bundled fonts, for
instance), that file governs it.

## Trademark

"Milvago" and the Milvago logo are trademarks of Milvago AI, LLC. The AGPL grants rights on
the code, not on the name or the logo: a modified distribution must not present itself as
Milvago or use the logo in a way that suggests endorsement.

## What AGPL-3.0 asks of an operator

Running a **modified** copy of the server or the console as a network service obliges you
to offer its users the corresponding source of that copy. Running it unmodified carries no
such obligation.

## The rest of Milvago

- **Endpoint agent and browser extension** — Apache-2.0, in their own repository. They are
  installed on end-user machines by IT teams: a permissive license with an explicit patent
  grant. They talk to this server only over its network API; no code is linked across.
- **Enterprise modules** — proprietary, not part of this repository, neither in source nor
  in the build produced here.

## Third-party dependencies

They keep their own licenses. See `THIRD-PARTY.md` and the lock files.
