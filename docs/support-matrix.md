---
title: Linux support matrix
description: Supported, best-effort, and unsupported distributions, package families, and architectures.
---

This document defines the official Linux **managed-host** support boundary for
Praxis 1.0: which distributions, package-manager families, and architectures
Praxis manages, and how far each lifecycle capability is validated.

> **Scope.** This matrix is about the **fleet** — the Linux hosts Praxis
> enrolls and manages. It is **not** about the control-plane deployment
> (Praxis itself runs as container images via `docker compose`; see
> [production-hardening.md](production-hardening.md) for supported
> control-plane deployment shapes).

The boundary here is grounded in the code as it exists on this branch, not in
aspiration. Where a capability is implemented for a family but carries a known
distro-specific caveat, it is called out in
[Known distro-specific limitations](#known-distro-specific-limitations).

## Support tiers

| Tier | Meaning |
|---|---|
| **Supported** | Praxis implements and intends to validate the full lifecycle (enroll → facts → lifecycle/EOL → mirror → content profile → patch → reboot → rollback → compliance) on this target. Bugs here are release-blocking. |
| **Best-effort** | The host enrolls and core read paths work, but at least one lifecycle capability has a known gap, is unvalidated, or depends on a package manager Praxis does not fully service. Usable, not guaranteed. |
| **Unsupported** | Praxis may detect the host (facts collector recognizes the package manager) but does **not** service patching, rollback, or mirror trust for it in 1.0. Not recommended for managed use. |

## Package-manager families

Praxis collapses every reported package manager into one of three families.
Only **two families are serviceable** for patch execution, rollback, mirror
trust, and content profiles. The mapping is enforced in code
(`backend/app/services/patch_update_plan_service.py`).

| Family | Package managers mapped in | Serviceable? |
|---|---|---|
| `apt` | `apt`, `apt-get`, `dpkg` | Yes — deb mirrors, apt patch/rollback |
| `dnf` | `dnf`, `yum`, `rpm` | Yes — rpm mirrors, dnf patch/rollback |
| `unknown` | anything else (`zypper`, `pacman`, `apk`, …) | No — rejected as `unsupported_package_family` |

A host whose family resolves to `unknown` is refused at patch dispatch and
rollback with the structured error `unsupported_package_family`.

## Architectures

| Architecture | Status | Notes |
|---|---|---|
| `x86_64` / `amd64` | Supported | Agent ships an amd64 build; SSH transport is architecture-neutral. |
| `aarch64` / `arm64` | Supported | Agent ships an arm64 build (CI cross-compiles both). |
| other (armv7, ppc64le, s390x, riscv64) | Unsupported | No agent build is published; not validated. |

## Distro / release matrix

Dates are standard upstream EOL from the hand-maintained
`backend/app/db/seed_data/distro_lifecycle.json` snapshot (`as_of`
2026-07-16). "ESM/extended" means the distro is past standard EOL but still
receiving extended/ESM updates.

### Supported

| Distro | Releases | Family | Standard EOL |
|---|---|---|---|
| Ubuntu LTS | 22.04, 24.04, 26.04 | `apt` | 2027-06 / 2029-06 / 2031-06 |
| Debian | 13 | `apt` | 2028-08 (LTS to 2030-06) |
| RHEL | 8, 9, 10 | `dnf` | 2029-05 / 2032-05 / 2035-05 |
| Rocky Linux | 8, 9, 10 | `dnf` | 2029-05 / 2032-05 / 2035-05 |
| AlmaLinux | 8, 9, 10 | `dnf` | 2029-03 / 2032-05 / 2035-05 |

### Best-effort

| Distro | Releases | Family | Why best-effort |
|---|---|---|---|
| Ubuntu LTS | 20.04 | `apt` | Past standard EOL (2025-04); ESM only. |
| Debian | 10, 11, 12 | `apt` | Past standard EOL; extended/LTS window only. |
| RHEL / CentOS | 7 | `dnf`→`yum` | yum-only host: the dnf dispatch invokes `dnf`, which is absent on EL7. See limitation #2. |
| Fedora | current | `dnf` | Maps to the dnf family, but no EOL seed and a fast release cadence; unvalidated. |
| Oracle Linux | 8, 9 | `dnf` | Maps to the dnf family; no EOL seed; unvalidated. |
| Amazon Linux | 2, 2023 | `dnf` | Maps to the dnf family; no EOL seed; unvalidated. |

### Unsupported

| Distro | Package manager | Reason |
|---|---|---|
| openSUSE / SLES | `zypper` | Detect-only; no patch/rollback/mirror support (`unsupported_package_family`). |
| Arch Linux | `pacman` | Detect-only; no patch/rollback/mirror support. |
| Alpine | `apk` | Detect-only; no patch/rollback/mirror support. |
| Any distro past EOL with no ESM/extended window | — | Out of lifecycle coverage. |

## Validation grid

This grid records the **code-path** status of each lifecycle capability per
supported family on this branch. It is a static (code + unit-test) assessment,
not a live-host run; live-host validation per release is tracked as a
follow-up release-checklist gate (see [below](#release-checklist-gate)).

Legend: ✅ implemented and covered by code/unit tests · ⚠️ implemented with a
known limitation · ✖️ not supported.

| Capability | deb family (Ubuntu/Debian) | EL family (RHEL/Rocky/Alma, dnf) |
|---|---|---|
| Enrollment (SSH bootstrap / agent) | ✅ | ✅ |
| Facts collection (`collect-facts.sh`) | ✅ | ✅ |
| Lifecycle / EOL | ✅ | ✅ |
| Mirror trust (signed repo) | ✅ (deb) | ✅ (rpm) |
| Content profile apply | ✅ | ✅ |
| Patch execution | ✅ (`apt-get install`) | ✅ (`dnf install`) |
| Reboot detection | ✅ (`/var/run/reboot-required`) | ⚠️ marker-file only; EL `needs-restarting` not checked (limitation #1) |
| Rollback feasibility | ✅ (apt) | ✅ (dnf) |
| Compliance probes | ✅ (operator-defined, read-only) | ✅ (operator-defined, read-only) |

Unsupported families (`zypper`/`pacman`/`apk`) are ✖️ for mirror trust,
content profile apply, patch execution, and rollback; they may still enroll
and collect facts on a best-effort basis.

## Known distro-specific limitations

1. **Reboot-required detection is Debian-centric.** Both the SSH facts
   collector (`backend/app/services/_assets/collect-facts.sh`) and the agent
   collector report `reboot_required=true` only when
   `/var/run/reboot-required` or `/run/reboot-required` exists — the
   Debian/Ubuntu `update-notifier` convention. EL-family hosts signal pending
   reboots through `dnf needs-restarting -r`, which the collector does **not**
   evaluate, so RHEL/Rocky/AlmaLinux hosts report `reboot_required=false` even
   when a reboot is pending. Reboot **policy** (`policy_always`,
   reboot-window scheduling) still works on EL hosts; only the
   `host_fact_reboot_required` signal underreports.

2. **The dnf family always invokes `dnf`.** Patch and rollback dispatch build
   `dnf install` / `dnf remove` for the entire dnf family, including hosts
   that report `package_manager=yum`. RHEL 7 / CentOS 7 ship `yum` without
   `dnf`, so patch execution fails there with a package-manager error. EL7 is
   therefore best-effort: facts and lifecycle work, but patching does not.

3. **Detect-only package managers are not serviceable.** `zypper`, `pacman`,
   and `apk` are recognized by the facts collector and surface in inventory,
   but resolve to the `unknown` family and are refused at patch/rollback with
   `unsupported_package_family`. Mirror trust and content-profile apply are
   deb/rpm only.

4. **EOL data covers the deb + EL families only.** `distro_lifecycle.json`
   seeds Ubuntu, Debian, RHEL, Rocky, and AlmaLinux. Fedora, Oracle Linux, and
   Amazon Linux map to the dnf family for patching but have no EOL rows, so
   lifecycle/EOL surfaces are blank for them.

## Release checklist gate

Before tagging a 1.0 release, this matrix should be confirmed against live
hosts for each **Supported** target:

- [ ] Enroll one host per supported family (deb + EL) and confirm facts.
- [ ] Confirm lifecycle/EOL surfaces populate from seeded data.
- [ ] Apply a signed mirror + content profile and confirm host `/etc` writes.
- [ ] Run a patch execution and a rollback on each family.
- [ ] Confirm reboot detection behavior, accounting for limitation #1 on EL.
- [ ] Run a compliance probe set.

Live-host run results should be recorded against this grid per release. Until
then, the grid above reflects code-path support only.
