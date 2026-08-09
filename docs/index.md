---
title: Praxis documentation
description: Operator documentation for Praxis, a self-hosted Linux fleet lifecycle control plane.
tableOfContents: false
---

Praxis is a self-hosted Linux fleet lifecycle control plane. It owns a Linux
fleet from host enrollment and inventory through package and content
lifecycle, patching, compliance evidence, and remediation, with one backend
acting as the policy authority. Access brokering is part of the product, not
the whole of it.

This documentation set is published on the web and bundled with the
application, so the same pages are available offline from an installed
Praxis.

## Start here

- [Requirements](requirements.md) covers what the control plane and managed
  hosts need before you install.
- [Install Praxis](install.md) walks through a production deployment with
  Docker Compose.
- [First run](first-run.md) covers the initial administrator, licensing, and
  the checks worth doing before you enroll anything.
- [Enroll hosts](enroll-hosts.md) explains SSH and thin-agent enrollment.
- [Getting started](getting-started.md) is a short tour of the interface once
  the fleet is populated.

## Understand the model

- [Fleet lifecycle architecture](fleet-lifecycle-architecture.md) describes the
  components and how work flows between them.
- [Security model and trust boundaries](security-model.md) states what each
  component is trusted to do.
- [Transports](transports.md) compares SSH and the thin agent and states which
  capabilities each one supports.
- [Editions and feature tiers](editions.md) explains what is in the free tier
  and what the paid tiers add.

## Run it day to day

The [how-to guides](guide-critical-updates.md) cover the workflows most
operators repeat: shipping critical updates, running patch windows, rolling
back, onboarding and offboarding people, granting temporary access,
reviewing access, exporting evidence, upgrading safely, and rotating a
licence.

## When something is wrong

Work through [troubleshooting](troubleshooting.md) first. If you still need
help, [support](support.md) lists what to gather so a report can be acted on.
