/**
 * Sidebar and information architecture for the documentation site.
 *
 * Page files are flat in `docs/` so that every documentation URL stays stable
 * and matches the in-application `/help/<slug>` path for the same page.
 * Grouping lives here rather than in the directory layout, so a page can be
 * regrouped without breaking a link someone has bookmarked or that the
 * application points at.
 *
 * Starlight fails the build on a slug that has no page, and
 * `scripts/check-docs-public-content.mjs` fails on a published page that no
 * group lists, so this stays in step with `docs/` in both directions.
 */
export const sidebar = [
  {
    label: 'Get started',
    items: [
      { slug: 'requirements' },
      { slug: 'install' },
      { slug: 'first-run' },
      { slug: 'enroll-hosts' },
      { slug: 'getting-started' },
    ],
  },
  {
    label: 'Concepts',
    items: [
      { slug: 'fleet-lifecycle-architecture' },
      { slug: 'security-model' },
      { slug: 'transports' },
      { slug: 'editions' },
    ],
  },
  {
    label: 'Using Praxis',
    items: [
      { slug: 'fleet-and-hosts' },
      { slug: 'packages' },
      { slug: 'patch-workflows' },
      { slug: 'jobs-and-scheduling' },
      { slug: 'ssh-and-security' },
      { slug: 'credentials-and-vault' },
      { slug: 'monitoring-and-alerts' },
      { slug: 'compliance-workflows' },
      { slug: 'mirrors-and-airgap' },
      { slug: 'reports-and-schedules' },
      { slug: 'settings' },
      { slug: 'admin' },
    ],
  },
  {
    label: 'How-to guides',
    items: [
      { slug: 'guide-add-first-system' },
      { slug: 'guide-critical-updates' },
      { slug: 'guide-patch-windows' },
      { slug: 'guide-rollback' },
      { slug: 'guide-onboarding-offboarding' },
      { slug: 'guide-temporary-access' },
      { slug: 'guide-access-review' },
      { slug: 'guide-evidence-export' },
      { slug: 'guide-safe-upgrade' },
      { slug: 'guide-license-rotation' },
    ],
  },
  {
    label: 'Operations',
    items: [
      { slug: 'production-hardening' },
      { slug: 'backup-restore' },
      { slug: 'airgap' },
      { slug: 'oidc-setup' },
      { slug: 'remediation-workflow' },
      { slug: 'scaling-assessment-500-hosts' },
      { slug: 'demo-walkthrough-operator' },
      { slug: 'demo-walkthrough-auditor' },
    ],
  },
  {
    label: 'Security',
    items: [
      { slug: 'access-revocation' },
      { slug: 'compliance-map' },
      { slug: 'audit-schema' },
    ],
  },
  {
    label: 'Release and upgrade',
    items: [
      { slug: 'licensing' },
      { slug: 'verify-release-artifacts' },
      { slug: 'upgrade' },
      { slug: 'upgrade-notes-1-0' },
      { slug: 'uninstall' },
    ],
  },
  {
    label: 'Reference',
    items: [
      { slug: 'support-matrix' },
      { slug: 'agent-capability-matrix' },
      { slug: 'agent-protocol' },
      { slug: 'reporting-contract' },
      { slug: 'eol-data' },
      { slug: 'browser-support' },
      { slug: 'known-limitations' },
    ],
  },
  {
    label: 'Troubleshooting and support',
    items: [{ slug: 'troubleshooting' }, { slug: 'support' }],
  },
];
