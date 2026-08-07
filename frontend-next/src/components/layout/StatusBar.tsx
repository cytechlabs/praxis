import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Settings, HelpCircle, Command, ChevronRight } from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import BuildInfo from './BuildInfo';

interface StatusBarProps {
  onOpenPalette: () => void;
}

const pathLabels: Record<string, string> = {
  'fleet-dashboard': 'Fleet Dashboard',
  'system-management': 'System Management',
  'all-systems': 'All Systems',
  'system-groups': 'System Groups',
  'register': 'Register System',
  'vault-management': 'Vault Management',
  'system': 'System Details',
  'edit': 'Edit',
  'credentials': 'Credentials',
  'all': 'All',
  'add': 'Add',
  'ssh-security': 'SSH Security',
  'ssh': 'SSH',
  'command-execution': 'Command Execution',
  'command-history': 'Command History',
  'command-metrics': 'Command Metrics',
  'command-whitelist': 'Command Whitelist',
  'validation-rules': 'Validation Rules',
  'approval-queue': 'Approval Queue',
  'package-management': 'Packages',
  'inventory': 'Inventory',
  'available-updates': 'Available Updates',
  'security-updates': 'Security Updates',
  'update-history': 'Update History',
  'repository-status': 'Repository Status',
  'fleet-search': 'Fleet Search',
  'job-scheduling': 'Jobs',
  'active-jobs': 'Active Jobs',
  'scheduled-jobs': 'Scheduled Jobs',
  'job-history': 'Job History',
  'job-templates': 'Job Templates',
  'failed-jobs': 'Failed Jobs',
  'maintenance-windows': 'Maintenance Windows',
  'monitoring-reporting': 'Monitoring',
  'system-status': 'System Status',
  'system-comparison': 'System Comparison',
  'package-reports': 'Package Reports',
  'audit-logs': 'Config Audit',
  'fleet-operations-history': 'Fleet Operations',
  'activity-feed': 'Activity Feed',
  'analytics': 'Analytics',
  'settings': 'Settings',
  'preferences': 'Preferences',
  'help': 'Help',
};

const StatusBar: React.FC<StatusBarProps> = ({ onOpenPalette }) => {
  const { user } = useAuth();
  const pathname = usePathname();

  const breadcrumbs = (pathname || '')
    .split('/')
    .filter(Boolean)
    .filter((seg) => !/^\d+$/.test(seg)) // filter out numeric IDs
    .map((segment) => pathLabels[segment] || segment.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()));

  return (
    <div className="flex items-center justify-between px-4 py-1.5 bg-surface border-t border-border/40 text-xs text-content-subtle">
      <div className="flex items-center gap-2">
        {breadcrumbs.length > 0 ? (
          breadcrumbs.map((crumb, i) => (
            <React.Fragment key={i}>
              {i > 0 && <ChevronRight size={10} className="text-content-subtle" />}
              <span className={i === breadcrumbs.length - 1 ? 'text-content-muted' : 'text-content-subtle'}>
                {crumb}
              </span>
            </React.Fragment>
          ))
        ) : (
          <span>Dashboard</span>
        )}
      </div>
      <div className="flex items-center gap-4">
        <button
          onClick={onOpenPalette}
          className="flex items-center gap-1.5 hover:text-content transition-colors"
        >
          <Command size={11} />
          <span>Ctrl+K</span>
        </button>
        <span className="text-content-subtle">|</span>
        <Link href="/preferences" className="hover:text-content transition-colors">
          {user?.username || 'user'}
        </Link>
        <span className="text-content-subtle">|</span>
        <Link href="/settings" className="hover:text-content transition-colors flex items-center gap-1">
          <Settings size={11} />
          Settings
        </Link>
        <Link href="/help" className="hover:text-content transition-colors flex items-center gap-1">
          <HelpCircle size={11} />
          Help
        </Link>
        <span className="text-content-subtle">|</span>
        {/* PRA-341: compact build identity - bottom-right, opens the About panel. */}
        <BuildInfo />
      </div>
    </div>
  );
};

export default StatusBar;
