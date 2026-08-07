import React from 'react';
import {
  LayoutDashboard, Server, Users, Filter, PlusCircle, Activity, Lock,
  ClipboardCheck, ClipboardList, Video, UserCheck, Terminal, Shield, AlertCircle,
  History, BarChart2, Search, Box, Download, Package, KeyRound, Database,
  PlayCircle, Calendar, FileText, Bookmark, Clock, Key, Vault, FileSearch,
  Bell, Layers, BarChart, PieChart, List, Settings, HelpCircle,
} from 'lucide-react';

/**
 * PRA-273 (workspace tabs): the single source of truth for the top-bar workspace
 * tabs, the floating command drawer, and the Ctrl+K palette — so all three stay
 * aligned instead of drifting.
 *
 * Six flat workspaces replace the old 10 dropdown menus. Each opens a compact
 * floating drawer with exactly three sections: Pages (destinations), Actions
 * (imperative entry points), Activity (needs-attention / recent context). App &
 * user settings are NOT a workspace — they live behind the user icon and Ctrl+K
 * (`SYSTEM_ITEMS`).
 */

export interface WorkspaceItem {
  id: string;
  label: string;
  path: string;
  icon: React.ReactNode;
  /** PRA-132 paid-edition feature — shown with a "Pro" marker. */
  paid?: boolean;
  /** Extra command-palette search terms. */
  keywords?: string;
  /** Extra path prefixes that mark this item's workspace active (detail pages). */
  match?: string[];
}

export interface Workspace {
  id: string;
  label: string;
  pages: WorkspaceItem[];
  actions: WorkspaceItem[];
  activity: WorkspaceItem[];
}

const sz = 15;

export const WORKSPACES: Workspace[] = [
  {
    id: 'operate',
    label: 'Operate',
    pages: [
      { id: 'fleet-dashboard', label: 'Dashboard', path: '/fleet-dashboard', icon: <LayoutDashboard size={sz} />, keywords: 'home overview fleet' },
      { id: 'all-systems', label: 'All Systems', path: '/system-management/all-systems', icon: <Server size={sz} />, match: ['/system-management/system', '/system-management/edit', '/hosts'] },
      { id: 'system-groups', label: 'System Groups', path: '/system-management/system-groups', icon: <Users size={sz} /> },
      { id: 'smart-groups', label: 'Smart Groups', path: '/system-management/smart-groups', icon: <Filter size={sz} /> },
      { id: 'active-sessions', label: 'Active Sessions', path: '/access/active-sessions', icon: <Activity size={sz} /> },
      { id: 'session-locks', label: 'Session Locks', path: '/access/session-locks', icon: <Lock size={sz} />, paid: true },
      { id: 'session-approvals', label: 'Session Approvals', path: '/access/session-approvals', icon: <ClipboardCheck size={sz} />, paid: true },
      { id: 'access-reviews', label: 'Access Reviews', path: '/access/access-reviews', icon: <ClipboardList size={sz} />, paid: true },
      { id: 'session-recordings', label: 'Session Recordings', path: '/recordings', icon: <Video size={sz} /> },
      { id: 'access-requests', label: 'Access Requests', path: '/access-requests', icon: <UserCheck size={sz} /> },
      { id: 'command-history', label: 'Command History', path: '/ssh/command-history', icon: <History size={sz} /> },
      { id: 'command-metrics', label: 'Command Metrics', path: '/ssh/command-metrics', icon: <BarChart2 size={sz} />, paid: true },
    ],
    actions: [
      { id: 'register-system', label: 'Register System', path: '/system-management/register', icon: <PlusCircle size={sz} /> },
      { id: 'command-execution', label: 'Run Command', path: '/ssh/command-execution', icon: <Terminal size={sz} />, keywords: 'ssh run execute' },
      { id: 'command-whitelist', label: 'Command Whitelist', path: '/ssh/command-whitelist', icon: <Shield size={sz} /> },
      { id: 'validation-rules', label: 'Validation Rules', path: '/ssh/validation-rules', icon: <AlertCircle size={sz} /> },
      { id: 'approval-queue', label: 'Approval Queue', path: '/ssh/approval-queue', icon: <FileSearch size={sz} />, paid: true },
    ],
    activity: [
      { id: 'op-unreachable', label: 'Unreachable systems', path: '/system-management/all-systems?status=Unreachable', icon: <AlertCircle size={sz} />, keywords: 'down offline degraded' },
      { id: 'op-active-sessions', label: 'Active sessions', path: '/access/active-sessions', icon: <Activity size={sz} /> },
    ],
  },
  {
    id: 'update',
    label: 'Update',
    pages: [
      { id: 'package-inventory', label: 'Package Inventory', path: '/package-management/inventory', icon: <Box size={sz} /> },
      { id: 'available-updates', label: 'Available Updates', path: '/package-management/available-updates', icon: <Download size={sz} /> },
      { id: 'security-updates', label: 'Security Updates', path: '/package-management/security-updates', icon: <Shield size={sz} />, keywords: 'critical cve patch' },
      { id: 'update-history', label: 'Update History', path: '/package-management/update-history', icon: <History size={sz} /> },
      { id: 'repository-status', label: 'Repository Status', path: '/package-management/repository-status', icon: <Package size={sz} /> },
      { id: 'patch-policies', label: 'Patch Policies', path: '/patch-policies/all', icon: <Shield size={sz} />, match: ['/patch-policies'], keywords: 'fleet default binding' },
      { id: 'patch-advisories', label: 'Patch Advisories', path: '/patch-advisories/all', icon: <Shield size={sz} />, match: ['/patch-advisories'], keywords: 'usn dsa rhsa cve applicable' },
      { id: 'update-plans', label: 'Update Plans', path: '/patch-update-plans/all', icon: <ClipboardList size={sz} />, match: ['/patch-update-plans'] },
    ],
    actions: [
      { id: 'fleet-search', label: 'Fleet Package Search', path: '/package-management/fleet-search', icon: <Search size={sz} />, keywords: 'find package across fleet' },
    ],
    activity: [
      { id: 'up-available', label: 'Available updates', path: '/package-management/available-updates', icon: <Download size={sz} /> },
      { id: 'up-security', label: 'Critical security updates', path: '/package-management/security-updates', icon: <Shield size={sz} /> },
    ],
  },
  {
    id: 'secure',
    label: 'Secure',
    pages: [
      { id: 'all-credentials', label: 'All Credentials', path: '/credentials/all', icon: <Key size={sz} />, match: ['/credentials/edit'] },
      { id: 'vault-management', label: 'Vault Management', path: '/system-management/vault-management', icon: <Vault size={sz} /> },
      { id: 'ssh-security', label: 'SSH Security', path: '/ssh-security', icon: <Shield size={sz} /> },
      { id: 'audit-log', label: 'Audit Log', path: '/audit', icon: <FileSearch size={sz} />, keywords: 'audit events sink' },
    ],
    actions: [
      { id: 'add-credential', label: 'Add Credential', path: '/credentials/add', icon: <Lock size={sz} /> },
    ],
    activity: [
      { id: 'sec-audit', label: 'Recent audit events', path: '/audit', icon: <FileSearch size={sz} /> },
    ],
  },
  {
    id: 'automate',
    label: 'Automate',
    pages: [
      { id: 'active-jobs', label: 'Active Jobs', path: '/job-scheduling/active-jobs', icon: <PlayCircle size={sz} /> },
      { id: 'scheduled-jobs', label: 'Scheduled Jobs', path: '/job-scheduling/scheduled-jobs', icon: <Calendar size={sz} /> },
      { id: 'job-history', label: 'Job History', path: '/job-scheduling/job-history', icon: <FileText size={sz} /> },
      { id: 'failed-jobs', label: 'Failed Jobs', path: '/job-scheduling/failed-jobs', icon: <AlertCircle size={sz} /> },
      { id: 'maintenance-windows', label: 'Maintenance Windows', path: '/job-scheduling/maintenance-windows', icon: <Clock size={sz} /> },
      { id: 'mirrors', label: 'Mirrors', path: '/mirrors/all', icon: <Database size={sz} />, match: ['/mirrors'] },
      { id: 'channels', label: 'Channels', path: '/content-channels/all', icon: <Database size={sz} />, match: ['/content-channels'] },
      { id: 'profiles', label: 'Profiles', path: '/content-profiles/all', icon: <Database size={sz} />, match: ['/content-profiles'] },
      { id: 'airgap-keys', label: 'Airgap Keys', path: '/airgap', icon: <KeyRound size={sz} />, keywords: 'signing key rotate trust pin bundle' },
    ],
    actions: [
      { id: 'job-templates', label: 'Job Templates', path: '/job-scheduling/job-templates', icon: <Bookmark size={sz} />, keywords: 'new job create' },
    ],
    activity: [
      { id: 'au-failed', label: 'Failed jobs', path: '/job-scheduling/failed-jobs', icon: <AlertCircle size={sz} /> },
      { id: 'au-active', label: 'Active jobs', path: '/job-scheduling/active-jobs', icon: <PlayCircle size={sz} /> },
    ],
  },
  {
    id: 'verify',
    label: 'Verify',
    pages: [
      { id: 'alerts', label: 'Alerts', path: '/monitoring-reporting/alerts', icon: <Bell size={sz} />, keywords: 'notifications unread bell' },
      { id: 'system-status', label: 'System Status', path: '/monitoring-reporting/system-status', icon: <Activity size={sz} /> },
      { id: 'system-comparison', label: 'System Comparison', path: '/monitoring-reporting/system-comparison', icon: <Layers size={sz} /> },
      { id: 'baselines', label: 'Baselines', path: '/monitoring-reporting/baselines', icon: <ClipboardCheck size={sz} /> },
      { id: 'drift', label: 'Drift', path: '/monitoring-reporting/drift', icon: <AlertCircle size={sz} /> },
      { id: 'compliance-dashboard', label: 'Compliance Dashboard', path: '/compliance', icon: <LayoutDashboard size={sz} />, keywords: 'cis overview' },
      { id: 'compliance-policies', label: 'Compliance Policies', path: '/compliance/policies', icon: <ClipboardList size={sz} /> },
      { id: 'compliance-remediation', label: 'Compliance Remediation', path: '/compliance/remediation', icon: <ClipboardCheck size={sz} /> },
    ],
    actions: [
      { id: 'compliance-starter-pack', label: 'Compliance Starter Pack', path: '/compliance/starter-pack', icon: <Bookmark size={sz} />, keywords: 'cis seed' },
    ],
    activity: [
      { id: 've-alerts', label: 'Alerts', path: '/monitoring-reporting/alerts', icon: <Bell size={sz} /> },
      { id: 've-drift', label: 'Drift', path: '/monitoring-reporting/drift', icon: <AlertCircle size={sz} /> },
    ],
  },
  {
    id: 'report',
    label: 'Report',
    pages: [
      { id: 'package-reports', label: 'Package Reports', path: '/monitoring-reporting/package-reports', icon: <FileSearch size={sz} /> },
      { id: 'fleet-operations', label: 'Fleet Operations', path: '/monitoring-reporting/fleet-operations-history', icon: <History size={sz} /> },
      { id: 'analytics', label: 'Analytics', path: '/monitoring-reporting/analytics', icon: <PieChart size={sz} /> },
      { id: 'config-audit', label: 'Config Audit', path: '/monitoring-reporting/audit-logs', icon: <List size={sz} />, keywords: 'system config changes' },
    ],
    actions: [],
    activity: [
      { id: 're-activity-feed', label: 'Activity Feed', path: '/monitoring-reporting/activity-feed', icon: <BarChart size={sz} />, keywords: 'recent events' },
    ],
  },
];

/**
 * App/user settings — NOT a workspace tab. Reachable behind the user icon and via
 * Ctrl+K only, per the approved direction (no Configure workspace).
 */
export const SYSTEM_ITEMS: WorkspaceItem[] = [
  { id: 'settings', label: 'Settings', path: '/settings', icon: <Settings size={sz} /> },
  { id: 'preferences', label: 'Preferences', path: '/preferences', icon: <Settings size={sz} />, keywords: 'profile account user' },
  { id: 'help', label: 'Help', path: '/help', icon: <HelpCircle size={sz} /> },
];

/** Base path without query string, for matching and de-duplication. */
function basePath(path: string): string {
  return path.split('?')[0];
}

function isUnderPrefix(pathname: string, prefix: string): boolean {
  return pathname === prefix || pathname.startsWith(prefix + '/');
}

/** True when the pathname belongs to this workspace (any page/action/activity item). */
export function isWorkspaceActive(pathname: string | null | undefined, ws: Workspace): boolean {
  if (!pathname) return false;
  const items = [...ws.pages, ...ws.actions, ...ws.activity];
  return items.some((item) => {
    if (isUnderPrefix(pathname, basePath(item.path))) return true;
    return (item.match ?? []).some((m) => isUnderPrefix(pathname, m));
  });
}

/** The workspace that owns the current route (longest matching item path wins). */
export function findActiveWorkspace(pathname: string | null | undefined): Workspace | undefined {
  if (!pathname) return undefined;
  let best: Workspace | undefined;
  let bestLen = -1;
  for (const ws of WORKSPACES) {
    for (const item of [...ws.pages, ...ws.actions, ...ws.activity]) {
      const matched =
        isUnderPrefix(pathname, basePath(item.path)) ||
        (item.match ?? []).some((m) => isUnderPrefix(pathname, m));
      if (matched && basePath(item.path).length > bestLen) {
        best = ws;
        bestLen = basePath(item.path).length;
      }
    }
  }
  return best;
}

/**
 * Every unique destination for the command palette (Ctrl+K), de-duplicated by
 * full path and tagged with the workspace it belongs to. Guarantees every route
 * remains discoverible in Ctrl+K. `System` items carry the 'System' group.
 */
export interface PaletteDestination extends WorkspaceItem {
  group: string;
}

export const PALETTE_DESTINATIONS: PaletteDestination[] = (() => {
  const seen = new Set<string>();
  const out: PaletteDestination[] = [];
  const push = (item: WorkspaceItem, group: string) => {
    if (seen.has(item.path)) return;
    seen.add(item.path);
    out.push({ ...item, group });
  };
  for (const ws of WORKSPACES) {
    for (const item of [...ws.pages, ...ws.actions, ...ws.activity]) push(item, ws.label);
  }
  for (const item of SYSTEM_ITEMS) push(item, 'System');
  return out;
})();
