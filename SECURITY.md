# Security Policy

We take the security of Praxis seriously. Thank you for helping keep Praxis and
its users safe by disclosing vulnerabilities responsibly.

## Supported versions

Security fixes are provided for the current 1.x release line. Please make sure you
can reproduce an issue on a current release before reporting it.

| Version | Supported |
| --- | --- |
| 1.x (current) | Yes |
| Older / pre-1.0 | No |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Instead, use one of the following private channels:

- Preferred: open a private advisory via GitHub Security Advisories
  ("Report a vulnerability" under the repository's **Security** tab).
- Or email **security@praxisfleet.com**.

To help us triage quickly, please include as much of the following as you can:

- The type of issue and the component affected (backend, frontend, agent,
  deployment).
- Affected version(s) or commit.
- Step-by-step instructions to reproduce.
- Proof-of-concept or exploit code, if available.
- The impact, including how an attacker might exploit the issue.

## What to expect

- **Acknowledgement:** we aim to acknowledge your report within a few business
  days.
- **Assessment:** we will investigate, confirm the issue, and determine the
  affected versions.
- **Fix and disclosure:** we will work on a fix and coordinate a disclosure
  timeline with you. We ask that you keep the report confidential until a fix is
  available and users have had a reasonable opportunity to update.
- **Credit:** with your permission, we are happy to credit you in the advisory
  once the issue is resolved.

## Scope

This policy covers the Praxis code in this repository. Vulnerabilities in
third-party dependencies should generally be reported upstream to the relevant
project; if a dependency issue is exploitable through Praxis, we still want to
hear about it so we can update or mitigate.
