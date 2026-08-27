import { describe, it, expect } from 'vitest';
import {
  WORKSPACES,
  SYSTEM_ITEMS,
  PALETTE_DESTINATIONS,
  findActiveWorkspace,
} from './workspaces';

// Every current static route (the pre-PRA-273 nav surface). Each must remain
// discoverible via Ctrl+K (PALETTE_DESTINATIONS) — the route audit, enforced.
const REQUIRED_ROUTES = [
  '/fleet-dashboard', '/system-management/all-systems', '/system-management/system-groups',
  '/system-management/smart-groups', '/system-management/onboard',
  '/credentials/all', '/credentials/add', '/system-management/vault-management', '/ssh-security',
  '/access/active-sessions', '/access/session-locks', '/access/session-approvals',
  '/access/access-reviews', '/recordings', '/access-requests', '/audit',
  '/ssh/command-execution', '/ssh/command-whitelist', '/ssh/validation-rules',
  '/ssh/approval-queue', '/ssh/command-history', '/ssh/command-metrics',
  '/package-management/fleet-search', '/package-management/inventory',
  '/package-management/available-updates', '/package-management/security-updates',
  '/package-management/update-history', '/package-management/repository-status',
  '/patch-policies/all', '/patch-advisories/all', '/patch-update-plans/all',
  '/mirrors/all', '/content-channels/all', '/content-profiles/all', '/airgap',
  '/job-scheduling/active-jobs', '/job-scheduling/scheduled-jobs', '/job-scheduling/job-history',
  '/job-scheduling/job-templates', '/job-scheduling/failed-jobs', '/job-scheduling/maintenance-windows',
  '/monitoring-reporting/alerts', '/monitoring-reporting/system-status',
  '/monitoring-reporting/system-comparison', '/monitoring-reporting/baselines',
  '/monitoring-reporting/drift', '/compliance', '/compliance/policies',
  '/compliance/remediation', '/compliance/starter-pack',
  '/monitoring-reporting/package-reports', '/monitoring-reporting/fleet-operations-history',
  '/monitoring-reporting/activity-feed', '/monitoring-reporting/analytics',
  '/monitoring-reporting/audit-logs', '/settings', '/preferences', '/help',
];

describe('workspace registry', () => {
  it('has exactly the six approved workspaces and no Configure', () => {
    expect(WORKSPACES.map((w) => w.label)).toEqual([
      'Operate', 'Update', 'Secure', 'Automate', 'Verify', 'Report',
    ]);
    expect(WORKSPACES.some((w) => /configure/i.test(w.label))).toBe(false);
  });

  it('each workspace has Pages, Actions, and Activity sections', () => {
    for (const ws of WORKSPACES) {
      expect(Array.isArray(ws.pages)).toBe(true);
      expect(ws.pages.length).toBeGreaterThan(0);
      expect(Array.isArray(ws.actions)).toBe(true);
      expect(Array.isArray(ws.activity)).toBe(true);
      expect(ws.activity.length).toBeGreaterThan(0);
    }
  });

  it('keeps settings out of the workspace tabs (System is palette-only)', () => {
    const workspacePaths = WORKSPACES.flatMap((w) =>
      [...w.pages, ...w.actions, ...w.activity].map((i) => i.path),
    );
    for (const p of ['/settings', '/preferences', '/help']) {
      expect(workspacePaths).not.toContain(p);
      expect(SYSTEM_ITEMS.map((i) => i.path)).toContain(p);
    }
  });
});

describe('Ctrl+K route audit', () => {
  it('every current route is discoverible in the command palette', () => {
    const palettePaths = new Set(PALETTE_DESTINATIONS.map((d) => d.path));
    for (const route of REQUIRED_ROUTES) {
      expect(palettePaths.has(route)).toBe(true);
    }
  });

  it('palette destinations are de-duplicated by path', () => {
    const paths = PALETTE_DESTINATIONS.map((d) => d.path);
    expect(new Set(paths).size).toBe(paths.length);
  });
});

describe('active workspace matching', () => {
  it('resolves the owning workspace for each area', () => {
    expect(findActiveWorkspace('/fleet-dashboard')?.id).toBe('operate');
    expect(findActiveWorkspace('/package-management/security-updates')?.id).toBe('update');
    expect(findActiveWorkspace('/credentials/all')?.id).toBe('secure');
    expect(findActiveWorkspace('/job-scheduling/failed-jobs')?.id).toBe('automate');
    expect(findActiveWorkspace('/compliance/policies')?.id).toBe('verify');
    expect(findActiveWorkspace('/monitoring-reporting/analytics')?.id).toBe('report');
  });

  it('routes detail pages to their workspace via match prefixes', () => {
    expect(findActiveWorkspace('/system-management/system/5')?.id).toBe('operate');
    expect(findActiveWorkspace('/credentials/edit/2')?.id).toBe('secure');
    expect(findActiveWorkspace('/patch-advisories/USN-1')?.id).toBe('update');
    expect(findActiveWorkspace('/content-channels/9')?.id).toBe('automate');
  });

  it('returns undefined for system/unknown routes (not a workspace)', () => {
    expect(findActiveWorkspace('/settings')).toBeUndefined();
    expect(findActiveWorkspace('/nope')).toBeUndefined();
  });
});
