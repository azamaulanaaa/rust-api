# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| older | No |

## Reporting a Vulnerability

Report vulnerabilities privately. Do not open a public issue.

Preferred channel: use GitHub's private vulnerability reporting for this repository.

Alternative: email the maintainer at `security@example.com`. Replace this placeholder with the real address before release.

Include these details in the report:

- A description of the issue.
- Steps to reproduce.
- The affected version or commit.
- The impact you expect.

## Response Timeline

- Acknowledgement within 72 hours.
- Triage and severity assessment within 7 days.
- A fix or mitigation plan within 30 days for confirmed issues.
- Public disclosure after a fix ships, or 90 days after the report, whichever comes first.

## Scope

In scope:

- OIDC authentication and session handling.
- JWT validation and JWKS refresh.
- Casbin authorization and policy storage.
- S3 file storage and multipart uploads.
- Secret handling for capability tokens and OIDC client secrets.
- Single-writer lease and fencing.

Out of scope:

- Vulnerabilities in dependencies. Report those upstream. This project tracks them in `deny.toml`.
- Misconfiguration of the operator's S3 bucket or identity provider.
- Denial of service from unbounded resource use that the operator can bound with `[limits]`.

## Responsible Disclosure

Give the maintainers time to fix the issue before public disclosure. Credit reporters in the release notes unless they ask otherwise.
