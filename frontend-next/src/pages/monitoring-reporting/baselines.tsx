import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import { toast } from 'sonner';
import { ClipboardCheck, Plus, Pencil, Trash2, Play, X, Package as PackageIcon, Cog } from 'lucide-react';
import MainLayout from '@/components/MainLayout';
import { PageHeader, Button, EmptyState, LoadingState } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { apiFetch, formatApiError } from '@/utils/api';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

type PkgCheck = 'required' | 'forbidden' | 'version_pin';
type SvcCheck = 'running' | 'stopped' | 'enabled' | 'disabled';

interface PkgRule { name: string; check: PkgCheck; version?: string }
interface SvcRule { name: string; check: SvcCheck }

interface Baseline {
  id: number;
  name: string;
  description: string | null;
  scope_smart_group_id: number | null;
  rules_json: { packages?: PkgRule[]; services?: SvcRule[] };
  enabled: boolean;
  schedule_interval_hours: number;
  last_run_at: string | null;
  status_counts: { compliant: number; drifted: number; error: number };
  created_at: string;
  updated_at: string;
}

interface SmartGroupOption { id: number; name: string; member_count: number }

const defaultBaseline = (): Pick<Baseline, 'name' | 'description' | 'scope_smart_group_id' | 'rules_json' | 'enabled' | 'schedule_interval_hours'> => ({
  name: '',
  description: '',
  scope_smart_group_id: null,
  rules_json: { packages: [], services: [] },
  enabled: true,
  schedule_interval_hours: 24,
});

const BaselinesPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const [baselines, setBaselines] = useState<Baseline[]>([]);
  const [smartGroups, setSmartGroups] = useState<SmartGroupOption[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<Baseline | null>(null);
  const [form, setForm] = useState(defaultBaseline());

  const fetchAll = useCallback(async () => {
    try {
      const [b, g] = await Promise.all([
        apiFetch('/api/backend/baselines'),
        apiFetch('/api/backend/smart-groups'),
      ]);
      if (b.ok) setBaselines((await b.json()).baselines || []);
      if (g.ok) setSmartGroups((await g.json()).smart_groups || []);
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  const openCreate = () => { setEditing(null); setForm(defaultBaseline()); setModalOpen(true); };
  const openEdit = (b: Baseline) => {
    setEditing(b);
    setForm({
      name: b.name,
      description: b.description || '',
      scope_smart_group_id: b.scope_smart_group_id,
      rules_json: {
        packages: b.rules_json.packages || [],
        services: b.rules_json.services || [],
      },
      enabled: b.enabled,
      schedule_interval_hours: b.schedule_interval_hours,
    });
    setModalOpen(true);
  };

  const save = async () => {
    if (!form.name.trim()) { toast.error('Name required'); return; }
    const pkgs = form.rules_json.packages || [];
    const svcs = form.rules_json.services || [];
    if (pkgs.length === 0 && svcs.length === 0) {
      toast.error('Add at least one package or service rule'); return;
    }
    const body: Record<string, unknown> = {
      name: form.name,
      description: form.description || null,
      rules_json: { packages: pkgs, services: svcs },
      enabled: form.enabled,
      schedule_interval_hours: form.schedule_interval_hours,
    };
    if (editing) {
      if (form.scope_smart_group_id == null) body.clear_scope = true;
      else body.scope_smart_group_id = form.scope_smart_group_id;
    } else {
      body.scope_smart_group_id = form.scope_smart_group_id ?? null;
    }
    const res = editing
      ? await apiFetch(`/api/backend/baselines/${editing.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      : await apiFetch('/api/backend/baselines', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (res.ok) {
      toast.success(editing ? 'Baseline updated' : 'Baseline created');
      setModalOpen(false); fetchAll();
    } else {
      const err = await res.json(); toast.error(formatApiError(err, 'Save failed'));
    }
  };

  const remove = async (b: Baseline) => {
    if (!confirm(`Delete baseline "${b.name}"?`)) return;
    const res = await apiFetch(`/api/backend/baselines/${b.id}`, { method: 'DELETE' });
    if (res.ok) { toast.success('Deleted'); fetchAll(); }
    else toast.error('Delete failed');
  };

  const runNow = async (b: Baseline) => {
    const res = await apiFetch(`/api/backend/baselines/${b.id}/run`, { method: 'POST' });
    if (res.ok) toast.success('Queued - results update in ~30-90s depending on fleet size');
    else toast.error('Failed to queue');
  };

  // --- rule list helpers ---
  const addPkg = () => setForm(f => ({ ...f, rules_json: { ...f.rules_json, packages: [...(f.rules_json.packages || []), { name: '', check: 'required' }] } }));
  const addSvc = () => setForm(f => ({ ...f, rules_json: { ...f.rules_json, services: [...(f.rules_json.services || []), { name: '', check: 'running' }] } }));
  const setPkg = (i: number, next: Partial<PkgRule>) => setForm(f => {
    const pkgs = [...(f.rules_json.packages || [])];
    pkgs[i] = { ...pkgs[i], ...next };
    if (next.check && next.check !== 'version_pin') delete pkgs[i].version;
    return { ...f, rules_json: { ...f.rules_json, packages: pkgs } };
  });
  const setSvc = (i: number, next: Partial<SvcRule>) => setForm(f => {
    const svcs = [...(f.rules_json.services || [])];
    svcs[i] = { ...svcs[i], ...next };
    return { ...f, rules_json: { ...f.rules_json, services: svcs } };
  });
  const delPkg = (i: number) => setForm(f => ({ ...f, rules_json: { ...f.rules_json, packages: (f.rules_json.packages || []).filter((_, j) => j !== i) } }));
  const delSvc = (i: number) => setForm(f => ({ ...f, rules_json: { ...f.rules_json, services: (f.rules_json.services || []).filter((_, j) => j !== i) } }));

  return (
    <MainLayout>
      <Head><title>Baselines - Praxis</title></Head>
      <PageHeader
        title="Baselines"
        subtitle="Define what should be installed, running, and enabled across the fleet. Drift checked on a schedule."
        actions={<div className="flex items-center gap-2"><Button variant="primary" icon={<Plus size={16} />} onClick={openCreate}>New Baseline</Button><HelpLink slug="monitoring-and-alerts" /></div>}
      />

      <div className="border border-border rounded-lg overflow-hidden">
        <table className="w-full text-sm text-content">
          <thead className="bg-red-900/30 text-content text-xs uppercase">
            <tr>
              <th className="px-4 py-3 text-left">Name</th>
              <th className="px-4 py-3 text-left">Scope</th>
              <th className="px-4 py-3 text-left">Schedule</th>
              <th className="px-4 py-3 text-center">Compliant</th>
              <th className="px-4 py-3 text-center">Drifted</th>
              <th className="px-4 py-3 text-center">Error</th>
              <th className="px-4 py-3 text-left">Last run</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {loading ? (
              <tr><td colSpan={8}><LoadingState label="Loading baselines" /></td></tr>
            ) : baselines.length === 0 ? (
              <tr><td colSpan={8}>
                <EmptyState
                  variant="not-configured"
                  title="No baselines configured"
                  description="Define the expected package and service state for your fleet, then Praxis tracks configuration drift against it."
                  action={<Button variant="secondary" size="sm" icon={<Plus size={15} />} onClick={openCreate}>New baseline</Button>}
                />
              </td></tr>
            ) : baselines.map(b => (
              <tr key={b.id} className="hover:bg-white/[0.03]">
                <td className="px-4 py-3 font-medium flex items-center gap-2"><ClipboardCheck size={14} className="text-red-400" />{b.name}</td>
                <td className="px-4 py-3 text-content-muted">
                  {b.scope_smart_group_id
                    ? (smartGroups.find(g => g.id === b.scope_smart_group_id)?.name || `#${b.scope_smart_group_id}`)
                    : 'Entire fleet'}
                </td>
                <td className="px-4 py-3 text-content-muted">every {b.schedule_interval_hours}h</td>
                <td className="px-4 py-3 text-center text-green-400">{b.status_counts.compliant}</td>
                <td className="px-4 py-3 text-center text-red-400">{b.status_counts.drifted}</td>
                <td className="px-4 py-3 text-center text-amber-400">{b.status_counts.error}</td>
                <td className="px-4 py-3 text-content-muted text-xs">{b.last_run_at ? formatTimestamp(b.last_run_at) : 'never'}</td>
                <td className="px-4 py-3 text-right">
                  <div className="flex justify-end gap-2">
                    <button onClick={() => runNow(b)} className="p-1 text-content-muted hover:text-green-400" title="Run now"><Play size={16} /></button>
                    <button onClick={() => openEdit(b)} className="p-1 text-content-muted hover:text-content" title="Edit"><Pencil size={16} /></button>
                    <button onClick={() => remove(b)} className="p-1 text-content-muted hover:text-red-400" title="Delete"><Trash2 size={16} /></button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-surface/70">
          <div className="bg-surface-overlay border border-border rounded-lg w-full max-w-3xl p-6 space-y-5 max-h-[92vh] overflow-y-auto">
            <h2 className="text-lg font-bold text-content">{editing ? 'Edit Baseline' : 'Create Baseline'}</h2>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-sm text-content-muted mb-1">Name</label>
                <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  className="w-full px-3 py-2 bg-surface-sunken border border-border rounded text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                  placeholder="e.g. Production baseline" />
              </div>
              <div>
                <label className="block text-sm text-content-muted mb-1">Scope</label>
                <select
                  value={form.scope_smart_group_id ?? ''}
                  onChange={e => setForm(f => ({ ...f, scope_smart_group_id: e.target.value ? Number(e.target.value) : null }))}
                  className="w-full px-3 py-2 bg-surface-sunken border border-border rounded text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                >
                  <option value="">Entire fleet</option>
                  {smartGroups.map(g => <option key={g.id} value={g.id}>{g.name} ({g.member_count} members)</option>)}
                </select>
              </div>
            </div>

            <div>
              <label className="block text-sm text-content-muted mb-1">Description</label>
              <input value={form.description || ''} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                className="w-full px-3 py-2 bg-surface-sunken border border-border rounded text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong" />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-sm text-content-muted mb-1">Check every (hours)</label>
                <input type="number" min={1} max={720} value={form.schedule_interval_hours}
                  onChange={e => setForm(f => ({ ...f, schedule_interval_hours: Number(e.target.value) || 24 }))}
                  className="w-full px-3 py-2 bg-surface-sunken border border-border rounded text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong" />
              </div>
              <div className="flex items-end gap-2">
                <input id="bl-enabled" type="checkbox" checked={form.enabled} onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))} className="accent-red-600" />
                <label htmlFor="bl-enabled" className="text-sm text-content pb-2">Enabled</label>
              </div>
            </div>

            {/* Packages section */}
            <div className="border border-border rounded p-3">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2 text-sm font-semibold text-content"><PackageIcon size={14} className="text-red-400" /> Packages</div>
                <Button variant="outline" onClick={addPkg} icon={<Plus size={12} />}>Add</Button>
              </div>
              {(form.rules_json.packages || []).length === 0 && (
                <div className="text-xs text-content-subtle italic">No package rules - click Add to require, forbid, or pin versions.</div>
              )}
              <div className="space-y-2">
                {(form.rules_json.packages || []).map((r, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <input value={r.name} onChange={e => setPkg(i, { name: e.target.value })} placeholder="package name (e.g. openssh-server)"
                      className="flex-1 bg-surface-sunken border border-border rounded text-xs text-content px-2 py-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong" />
                    <select value={r.check} onChange={e => setPkg(i, { check: e.target.value as PkgCheck })}
                      className="bg-surface-sunken border border-border rounded text-xs text-content px-2 py-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong">
                      <option value="required">required</option>
                      <option value="forbidden">forbidden</option>
                      <option value="version_pin">version_pin</option>
                    </select>
                    {r.check === 'version_pin' && (
                      <input value={r.version || ''} onChange={e => setPkg(i, { version: e.target.value })} placeholder="exact version"
                        className="w-32 bg-surface-sunken border border-border rounded text-xs text-content px-2 py-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong" />
                    )}
                    <button onClick={() => delPkg(i)} className="text-content-subtle hover:text-red-400"><X size={14} /></button>
                  </div>
                ))}
              </div>
            </div>

            {/* Services section */}
            <div className="border border-border rounded p-3">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2 text-sm font-semibold text-content"><Cog size={14} className="text-red-400" /> Services</div>
                <Button variant="outline" onClick={addSvc} icon={<Plus size={12} />}>Add</Button>
              </div>
              {(form.rules_json.services || []).length === 0 && (
                <div className="text-xs text-content-subtle italic">No service rules - click Add to require running, stopped, enabled, or disabled.</div>
              )}
              <div className="space-y-2">
                {(form.rules_json.services || []).map((r, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <input value={r.name} onChange={e => setSvc(i, { name: e.target.value })} placeholder="service unit (e.g. sshd, nginx)"
                      className="flex-1 bg-surface-sunken border border-border rounded text-xs text-content px-2 py-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong" />
                    <select value={r.check} onChange={e => setSvc(i, { check: e.target.value as SvcCheck })}
                      className="bg-surface-sunken border border-border rounded text-xs text-content px-2 py-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong">
                      <option value="running">running</option>
                      <option value="stopped">stopped</option>
                      <option value="enabled">enabled</option>
                      <option value="disabled">disabled</option>
                    </select>
                    <button onClick={() => delSvc(i)} className="text-content-subtle hover:text-red-400"><X size={14} /></button>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <Button variant="outline" onClick={() => setModalOpen(false)}>Cancel</Button>
              <Button variant="primary" onClick={save} disabled={!form.name}>{editing ? 'Update' : 'Create'}</Button>
            </div>
          </div>
        </div>
      )}
    </MainLayout>
  );
};

export default BaselinesPage;
