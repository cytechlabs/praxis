---
title: Requirements
description: What the control plane host and the managed hosts need before you install Praxis.
---

Read this before installing. Most failed first installs are a missing
prerequisite rather than a problem with Praxis.

## Control plane host

Praxis is distributed as container images and runs as a Docker Compose stack on
a single Linux host.

| Requirement | Detail |
|---|---|
| Operating system | A Linux host that runs current Docker Engine. Praxis is not supported on Docker Desktop for production. |
| Architecture | `amd64` or `arm64`. |
| Docker Engine | 24.0 or newer. |
| Docker Compose | v2.24 or newer. The compose files use the `!override` merge tag, which older versions ignore silently. |
| Disk | Dominated by whatever you keep, not by the application. Plan for the database and audit history, plus the full size of any package mirrors you sync. A single distribution mirror is commonly tens of gigabytes. |
| Outbound network | Access to the container registry to pull images, and to your package upstreams if you sync mirrors. Neither is needed after install in a disconnected deployment. See [airgap export and import](airgap.md). |

### Sizing

The supported topology runs a **single backend worker**, which is a correctness
requirement rather than a starting point: interactive session state is held in
the process that opened the session. The production entrypoint refuses to start
with more than one worker.

Because of that, control plane CPU and memory track the number of
**concurrent interactive sessions**, not the number of enrolled hosts. Enrolling
more hosts grows database rows and scheduled sweep work, which scales linearly
and cheaply. A fleet of 500 hosts with a handful of live terminal sessions sits
inside the validated envelope. See [capacity and scaling](scaling-assessment-500-hosts.md)
for the measurements behind that, and the dimensions worth watching as you grow.

### Ports

Only the reverse proxy is published to the network by default. The backend and
frontend publish no host ports, so the stack is unreachable from a browser
unless you start the proxy profile or front it with your own edge proxy.

| Port | Service | Needed for |
|---|---|---|
| 443 | Caddy | Browser and API access. |
| 80 | Caddy | Redirect to HTTPS, and certificate issuance in ACME mode. |
| 8443 | Agent broker | Inbound mTLS from thin agents. Only if you enroll agents. |

## Managed hosts

The supported boundary is stated in full in the
[Linux support matrix](support-matrix.md). In summary:

- The complete patch lifecycle is supported on the **deb** family (Debian,
  Ubuntu) and the **EL** family (RHEL, Rocky, AlmaLinux) on `amd64` and
  `arm64`.
- Other distributions may enroll and report inventory on a best-effort basis
  but are not serviced for package changes.

Every managed host needs one of the two transports:

- **SSH**, reachable from the control plane, with an account Praxis can use.
  This is the default and is required for interactive terminal sessions on any
  host.
- **The thin agent**, which dials out to the broker, for hosts the control
  plane cannot reach inbound.

[Transports](transports.md) explains which operations each one supports. They
are not equivalent, and choosing agent-only for a host removes interactive
sessions on that host.

### The account Praxis connects as

Use a dedicated automation account rather than a human login or bare `root`.
It needs:

- Password or SSH key authentication that you can store in the secrets service.
- A way to escalate for privileged work. `sudo` with a `NOPASSWD:` entry
  scoped to the commands Praxis runs is the recommended shape. Patch, rollback,
  and reboot dispatch refuse to run if the credential does not declare a valid
  escalation method, rather than failing opaquely as an unprivileged user.

See [credentials and secrets](credentials-and-vault.md) for how the credential
is stored and rotated.

## Browsers

Praxis is a browser application with a minimum supported viewport. See
[browser and viewport support](browser-support.md) for the supported browsers
and what degrades outside the supported range.

## Identity

Local accounts work out of the box. To use single sign-on you need an OIDC
provider that publishes a discovery document; Praxis does not ship one. See
[single sign-on setup](oidc-setup.md).

## Next

Continue to [install Praxis](install.md).
