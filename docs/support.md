---
title: Support
description: Where to report a problem, what to include so it can be acted on, and what not to send.
---

## Before reporting

Reproduce the problem on a current release if you can, and work through
[troubleshooting](troubleshooting.md) first. A large share of reports resolve
there, usually as a missing proxy profile, a sealed secrets service, or a
credential that cannot escalate.

Check [known limitations](known-limitations.md) and the
[Linux support matrix](support-matrix.md) as well. Some behaviour that looks
wrong is a stated boundary: inventory is broader than servicing, and interactive
sessions always use SSH even on agent-enrolled hosts.

## Security vulnerabilities

**Do not report a vulnerability through a public issue, pull request, or
discussion.**

Use a private GitHub Security Advisory, through **Report a vulnerability** on
the repository's Security tab, or email **security@cytechlabs.com**.

Include the component affected, the version, how to reproduce it, and the
impact including how an attacker might exploit it. Reports are acknowledged
within a few business days. Please keep the report confidential until a fix is
available; with your permission you will be credited in the advisory.

Vulnerabilities in third-party dependencies are generally best reported
upstream. If a dependency issue is exploitable through Praxis, report it here
as well.

## Bugs and questions

Open an issue on the project repository. One report per problem; a report
covering three unrelated symptoms is slower to resolve than three reports.

## What to include

A report that can be acted on without a round trip has:

- **The version.** For the control plane, the release you pinned in
  `PRAXIS_VERSION`, and the image digests if you have them. For the agent,
  `praxis-agent version --json`, which carries the full 40-character commit SHA.
  A `stamped` of `false` means a local build rather than a published release.
- **The deployment shape.** Bundled or external services, whether the proxy
  profile is running, and the TLS mode.
- **The exact error**, copied rather than paraphrased.
- **What you expected**, and what happened instead.
- **Steps to reproduce**, from a known starting state.
- **Scope.** One host or all of them; one transport or both; started after an
  upgrade or always.

For a host-level problem, add the transport, the credential's escalation
method, and whether other hosts sharing that credential behave the same way.
For an agent problem, add `systemctl status praxis-agent` and the relevant
journal lines.

## What not to include

Reports become public. Before pasting anything:

- **No secrets.** No passwords, private keys, tokens, `VAULT_TOKEN`, licence
  keys, or `.env` contents. Redact them rather than trimming them out, so the
  shape of the value is still visible.
- **No internal hostnames, addresses, or user identities** you would not
  publish. Replace them consistently, so `web-01` stays `web-01` throughout.
- **Screenshots are data.** Check the whole window, not the area you meant to
  capture: sidebars, tooltips, notification toasts, browser tabs, and the URL
  bar all leak.
- **Exports are data.** An evidence or audit export contains hostnames, package
  inventories, and user identities. Send a minimal excerpt, not the file.

If a secret has appeared anywhere in a report, rotate it. See
[credentials and secrets](credentials-and-vault.md).

## Getting a diagnosis faster

Say what you already ruled out. "Other hosts on the same credential work" or
"this started after upgrading from 1.0.0 to 1.0.1" removes most of the search
space in one line.

If it is a regression, the release you upgraded from is the single most useful
fact in the report.

## Commercial support

Enterprise arrangements above the self-serve tiers, including air-gapped
deployments and service level commitments, are sales-assisted. See
[editions and feature tiers](editions.md).
