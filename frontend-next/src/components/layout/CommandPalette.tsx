import React, { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/router';
import { Command } from 'cmdk';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';
import { useAuth } from '@/context/AuthContext';
import { apiFetch } from '@/utils/api';
import { fetchAllSystems, type SystemListItem } from '@/services/systemService';
import { PALETTE_DESTINATIONS } from '@/config/workspaces';
import {
  Terminal, AlertCircle, Search, Activity, RefreshCw, LogOut, Zap,
} from 'lucide-react';

type NavItem = {
  kind: 'nav';
  id: string;
  label: string;
  icon: React.ReactNode;
  path: string;
  group: string;
  keywords?: string;
};

type ActionItem = {
  kind: 'action';
  id: string;
  label: string;
  icon: React.ReactNode;
  group: string;
  keywords?: string;
  run: (ctx: ActionContext) => void | Promise<void>;
};

type CommandItem = NavItem | ActionItem;

interface ActionContext {
  router: ReturnType<typeof useRouter>;
  logout: () => Promise<void>;
  close: () => void;
}

// PRA-273: derive palette destinations from the SHARED workspace registry so the
// workspace tabs, the floating drawer, and Ctrl+K can never drift. Every unique
// route (deduped by full path) is here, keeping every route discoverable.
const navItems: NavItem[] = PALETTE_DESTINATIONS.map((d) => ({
  kind: 'nav' as const,
  id: d.id,
  label: d.label,
  icon: d.icon,
  path: d.path,
  group: d.group,
  keywords: d.keywords,
}));

const actionItems: ActionItem[] = [
  {
    kind: 'action',
    id: 'refresh-dashboard',
    label: 'Refresh dashboard',
    icon: <RefreshCw size={15} />,
    group: 'Actions',
    keywords: 'reload',
    run: async ({ router, close }) => {
      close();
      if (router.pathname === '/fleet-dashboard') {
        router.replace(router.asPath);
      } else {
        router.push('/fleet-dashboard');
      }
    },
  },
  {
    kind: 'action',
    id: 'check-all-systems',
    label: 'Check all systems (health probe)',
    icon: <Activity size={15} />,
    group: 'Actions',
    keywords: 'ping health probe',
    run: async ({ close }) => {
      close();
      try {
        const res = await apiFetch('/api/backend/health/check-all', { method: 'POST' });
        if (!res.ok) throw new Error('Health check failed');
        const data = await res.json();
        if (data.status === 'already_running') {
          toast.info(data.message || 'A fleet health check is already running');
        } else {
          toast.success(`Checked ${data.total} systems: ${data.ok} ok, ${data.failed} failed`);
        }
      } catch (err) {
        toast.error(err instanceof Error ? err.message : 'Health check failed');
      }
    },
  },
  {
    kind: 'action',
    id: 'jump-to-unreachable',
    label: 'View unreachable systems',
    icon: <AlertCircle size={15} />,
    group: 'Actions',
    keywords: 'down offline',
    run: ({ router, close }) => {
      close();
      router.push('/system-management/all-systems?status=Unreachable');
    },
  },
  {
    kind: 'action',
    id: 'jump-to-security-updates',
    label: 'View pending security updates',
    icon: <Zap size={15} />,
    group: 'Actions',
    keywords: 'patches cve',
    run: ({ router, close }) => {
      close();
      router.push('/package-management/security-updates');
    },
  },
  {
    kind: 'action',
    id: 'jump-to-failed-jobs',
    label: 'View failed jobs',
    icon: <AlertCircle size={15} />,
    group: 'Actions',
    keywords: 'errors',
    run: ({ router, close }) => {
      close();
      router.push('/job-scheduling/failed-jobs');
    },
  },
  {
    kind: 'action',
    id: 'logout',
    label: 'Log out',
    icon: <LogOut size={15} />,
    group: 'Actions',
    keywords: 'sign out exit',
    run: async ({ logout, close }) => {
      close();
      await logout();
    },
  },
];

const allCommands: CommandItem[] = [...actionItems, ...navItems];

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
}

const CommandPalette: React.FC<CommandPaletteProps> = ({ open, onClose }) => {
  const router = useRouter();
  const { logout } = useAuth();
  const [search, setSearch] = useState('');
  const [systems, setSystems] = useState<SystemListItem[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    setSearch('');
    const t = setTimeout(() => inputRef.current?.focus(), 50);
    // Fetch systems once per open so the Connect list stays fresh without
    // blocking palette open - failures are silent, the nav items still work.
    fetchAllSystems()
      .then(setSystems)
      .catch(() => {});
    return () => clearTimeout(t);
  }, [open]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        if (open) onClose();
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [open, onClose]);

  const handleSelect = (cmd: CommandItem) => {
    if (cmd.kind === 'nav') {
      onClose();
      router.push(cmd.path);
    } else {
      void cmd.run({ router, logout, close: onClose });
    }
  };

  const connectItems: NavItem[] = systems.map((s) => ({
    kind: 'nav',
    id: `connect-${s.id}`,
    label: `Connect to ${s.hostname}`,
    icon: <Terminal size={15} />,
    path: `/hosts/${s.id}/session`,
    group: 'Connect',
    keywords: `ssh shell session ${s.hostname} ${s.ip_address ?? ''}`,
  }));

  const combined: CommandItem[] = [...connectItems, ...allCommands];
  const groups = Array.from(new Set(combined.map((c) => c.group)));

  return (
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-[200]">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.1 }}
            className="absolute inset-0 bg-black/50 backdrop-blur-sm"
            onClick={onClose}
          />
          <div className="flex items-start justify-center pt-[20vh]">
            <motion.div
              initial={{ opacity: 0, scale: 0.96, y: -10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.96, y: -10 }}
              transition={{ duration: 0.12 }}
              className="relative w-full max-w-lg mx-4"
            >
              <Command
                className="bg-surface border border-border/60 rounded-xl shadow-2xl overflow-hidden"
                loop
              >
                <div className="flex items-center gap-2 px-4 border-b border-border">
                  <Search size={16} className="text-content-subtle flex-shrink-0" />
                  <Command.Input
                    ref={inputRef}
                    value={search}
                    onValueChange={setSearch}
                    placeholder="Search or run a command..."
                    className="w-full bg-transparent py-3.5 text-sm text-content placeholder:text-content-subtle focus:outline-none"
                  />
                  <kbd className="hidden sm:inline-flex items-center px-1.5 py-0.5 text-[10px] text-content-subtle bg-surface-overlay rounded border border-border-strong">
                    ESC
                  </kbd>
                </div>
                <Command.List className="max-h-80 overflow-y-auto py-2">
                  <Command.Empty className="px-4 py-8 text-center text-sm text-content-subtle">
                    No results found.
                  </Command.Empty>
                  {groups.map((group) => (
                    <Command.Group key={group} heading={group} className="px-2">
                      <div className="px-2 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-content-subtle">
                        {group}
                      </div>
                      {combined
                        .filter((c) => c.group === group)
                        .map((cmd) => (
                          <Command.Item
                            key={cmd.id}
                            value={`${cmd.label} ${cmd.keywords || ''}`}
                            onSelect={() => handleSelect(cmd)}
                            className="flex items-center gap-2.5 px-3 py-2 text-sm text-content-muted rounded-md cursor-pointer data-[selected=true]:bg-brand/10 data-[selected=true]:text-brand transition-colors mx-1"
                          >
                            {cmd.icon}
                            {cmd.label}
                          </Command.Item>
                        ))}
                    </Command.Group>
                  ))}
                </Command.List>
              </Command>
            </motion.div>
          </div>
        </div>
      )}
    </AnimatePresence>
  );
};

export default CommandPalette;
