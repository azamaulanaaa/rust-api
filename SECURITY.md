# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| older | No |

## Reporting a Vulnerability

Report vulnerabilities privately. Do not open a public issue.

Preferred channel: use GitHub's private vulnerability reporting for this repository:

https://github.com/azamaulanaaa/rust-api/security/advisories/new

This repository has no security email address. Use the GitHub report form.

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
- EAV schema and entity API, including schema defaults, entity validation, unique and index facts, and version checks.
- EAV rule scripts, including the Rhai sandbox, its operation limits, and its read and write capability sets.
- EAV condition-script visibility, including the rule read set, the hidden attributes and changes, and the visible entity identity and event metadata.
- EAV webhook egress, including the host allowlist, DNS resolution and address pinning, disabled system proxies, the body-only legacy signature, the timestamped `X-Signature-V2` signature, and the replay window in the signature verifier.
- EAV log action redaction, including secret-like parameter keys and URL user information and query values.
- EAV replica authorization, including the build-time grant filter and the read-time grant filter.

Out of scope:

- Vulnerabilities in dependencies. Report those upstream. This project tracks them in `deny.toml`.
- Misconfiguration of the operator's S3 bucket or identity provider.
- Denial of service from unbounded resource use that the operator can bound with `[limits]`.

## Responsible Disclosure

Give the maintainers time to fix the issue before public disclosure. Credit reporters in the release notes unless they ask otherwise.
