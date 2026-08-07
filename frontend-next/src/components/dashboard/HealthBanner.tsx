import React from 'react';
import Link from 'next/link';
import { CheckCircle2, AlertTriangle, ShieldAlert, Download, ChevronRight } from 'lucide-react';

interface HealthBannerProps {
  unreachable: number;
  // PRA-277: securityUpdates / pendingUpdates are total pending package-update
  // ROWS; systemsWith* are the distinct systems those rows span. The banner
  // reports both so a row total is never mislabelled as a systems count.
  securityUpdates: number;
  systemsWithSecurityUpdates: number;
  pendingUpdates: number;
  systemsWithUpdates: number;
  totalSystems: number;
}

// "on 1 system" vs "across N systems" - keeps the hero copy grammatical.
const systemsPhrase = (n: number): string =>
  n === 1 ? 'on 1 system' : `across ${n} systems`;

type Severity = 'critical' | 'warning' | 'info' | 'healthy';

interface BannerState {
  severity: Severity;
  icon: React.ReactNode;
  headline: string;
  detail: string;
  href: string;
  cta: string;
}

const HealthBanner: React.FC<HealthBannerProps> = ({
  unreachable,
  securityUpdates,
  systemsWithSecurityUpdates,
  pendingUpdates,
  systemsWithUpdates,
  totalSystems,
}) => {
  let state: BannerState;

  if (unreachable > 0) {
    state = {
      severity: 'critical',
      icon: <AlertTriangle size={20} />,
      headline: `${unreachable} system${unreachable === 1 ? '' : 's'} unreachable`,
      detail: 'Connectivity check failed - review credentials, firewall, and host status.',
      href: '/system-management/all-systems?status=Unreachable',
      cta: 'View unreachable systems',
    };
  } else if (securityUpdates > 0) {
    state = {
      severity: 'warning',
      icon: <ShieldAlert size={20} />,
      headline: `${securityUpdates} critical security update${securityUpdates === 1 ? '' : 's'} pending ${systemsPhrase(systemsWithSecurityUpdates)}`,
      detail: 'Patch these to close known vulnerabilities across your fleet.',
      href: '/package-management/security-updates',
      cta: 'Review security updates',
    };
  } else if (pendingUpdates > 0) {
    state = {
      severity: 'info',
      icon: <Download size={20} />,
      headline: `${pendingUpdates} package update${pendingUpdates === 1 ? '' : 's'} available ${systemsPhrase(systemsWithUpdates)}`,
      detail: 'No critical issues - apply updates at your convenience.',
      href: '/package-management/available-updates',
      cta: 'View available updates',
    };
  } else {
    state = {
      severity: 'healthy',
      icon: <CheckCircle2 size={20} />,
      headline: totalSystems > 0
        ? `All ${totalSystems} system${totalSystems === 1 ? '' : 's'} healthy`
        : 'No systems registered yet',
      detail: totalSystems > 0
        ? 'No outstanding issues. Last check is current.'
        : 'Register your first Linux system to start monitoring.',
      href: totalSystems > 0
        ? '/system-management/all-systems'
        : '/system-management/register',
      cta: totalSystems > 0 ? 'View fleet' : 'Register a system',
    };
  }

  const styles: Record<Severity, { bg: string; border: string; icon: string; text: string; cta: string }> = {
    critical: {
      bg: 'bg-red-950/40',
      border: 'border-red-800/60',
      icon: 'text-red-400 bg-red-500/10',
      text: 'text-red-200',
      cta: 'text-red-300 hover:text-red-200',
    },
    warning: {
      bg: 'bg-yellow-950/30',
      border: 'border-yellow-800/50',
      icon: 'text-yellow-400 bg-yellow-500/10',
      text: 'text-yellow-100',
      cta: 'text-yellow-300 hover:text-yellow-200',
    },
    info: {
      bg: 'bg-gray-900/60',
      border: 'border-gray-700/60',
      icon: 'text-gray-300 bg-gray-700/40',
      text: 'text-gray-200',
      cta: 'text-gray-300 hover:text-gray-100',
    },
    healthy: {
      bg: 'bg-emerald-950/30',
      border: 'border-emerald-800/40',
      icon: 'text-emerald-400 bg-emerald-500/10',
      text: 'text-emerald-100',
      cta: 'text-emerald-300 hover:text-emerald-200',
    },
  };

  const s = styles[state.severity];

  return (
    <Link
      href={state.href}
      className={`group flex items-start gap-4 ${s.bg} ${s.border} border rounded-lg px-5 py-4 mb-6 transition-colors hover:border-opacity-80 focus:outline-none focus:ring-2 focus:ring-red-500/40`}
    >
      <div className={`p-2 rounded-md ${s.icon} shrink-0`}>{state.icon}</div>
      <div className="flex-1 min-w-0">
        <div className={`text-base font-semibold ${s.text} tracking-tight`}>{state.headline}</div>
        <div className="text-xs text-gray-400 mt-0.5">{state.detail}</div>
      </div>
      <div className={`shrink-0 inline-flex items-center gap-1 text-sm font-medium ${s.cta} transition-colors`}>
        <span className="hidden sm:inline">{state.cta}</span>
        <ChevronRight size={16} className="transition-transform group-hover:translate-x-0.5" />
      </div>
    </Link>
  );
};

export default HealthBanner;
