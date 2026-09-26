# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Use GitHub's private vulnerability
reporting on this repository (*Security* → *Report a vulnerability*). That channel is private
between you and the maintainers until a fix exists.

Useful in a report:

- what an attacker gains, and from which position (unauthenticated visitor, member of an
  organization, holder of an API key, operator of the browser endpoint)
- the smallest sequence that reproduces it, and the version or commit it was observed on
- the effect you actually saw, rather than the effect you expect

Please do not include third-party data, real prompts or credentials in a report. A
description of the class of problem is enough to start; we will ask if we need more.

## What is in scope

The sources in this repository: the server and the console, as built from this tree. The
endpoint agent and its browser extension have their own repository. Anything that is not
here — hosted instances, signed packages, the Enterprise modules — is out of scope for this
repository's reports.

Findings that we treat as expected behavior rather than vulnerabilities:

- an HTTP public URL on a private test network when the operator has explicitly selected it;
  production operators should terminate HTTPS at a trusted reverse proxy
- the absence of Enterprise capabilities in this edition
- results obtained by first granting yourself administrative rights on the instance

## Supported versions

The tip of the default branch. This project publishes no long-term support branch: fixes go
to the default branch, and a release is cut from it.

## Handling

We acknowledge a report, investigate, and tell you what we found — including when we
conclude that there is nothing to fix. When a fix ships, the advisory credits the reporter
unless they ask otherwise.
