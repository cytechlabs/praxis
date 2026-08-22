import React, { useCallback, useEffect, useMemo, useState } from 'react';
import Head from 'next/head';
import { toast } from 'sonner';
import { Filter, Plus, Pencil, Trash2, RefreshCw, Users as UsersIcon, X, ChevronRight } from 'lucide-react';
import MainLayout from '@/components/MainLayout';
import { PageHeader, Button, StatusBadge, nativeSelectClass } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { apiFetch, formatApiError } from '@/utils/api';

type Op = 'and' | 'or';

interface FieldSpec { field: string; type: 'string' | 'enum' | 'bool' | 'number'; ops: string[] }

const FIELD_HINTS: Record<string, string> = {
  hostname: 'e.g. prod-web-01',
  ip_address: 'e.g. 10.0.0.5',
  os_version: 'version number only (e.g. 24.04)',
  update_policy: 'manual / auto / etc.',
  status: 'Active / Decommissioned',
  distro: 'Ubuntu / Debian / RHEL',
  group: 'static group name',
  tag: 'tag name',
  environment_type: 'production / staging / Testing / dev',
  has_pending_updates: 'true/false',
  has_security_updates: 'true/false',
  ca_trust_deployed: 'true/false',
  days_since_last_audit: 'integer days',
  // PRA-161 #1f: patch.* predicate hints. The backend's
  // /smart-groups/field-catalog endpoint exposes these dynamically;
  // the hint map only adds operator-friendly placeholder text.
  // Smart groups whose rules reference any patch.* field cannot be
  // bound as patch-policy targets - that's the slice 1e cycle guard,
  // enforced at bind time not save time.
  'patch.resolution_kind':
    'direct_host / static_group / smart_group / fleet_default / no_policy / conflict',
  'patch.effective_policy_slug': 'patch policy slug (e.g. weekly-security)',
  'patch.has_effective_policy': 'true/false',
  'patch.policy_requires_approval': 'true/false',
  'patch.rollout_cadence': 'immediate / staged',
  // PRA-163 #3 / #4: advisory.* predicate hints. Counts default to
  // zero for hosts with no applicability rows; has_open_advisories
  // is true iff applicable_count > 0. Unlike patch.* / ring.*, an
  // advisory.* smart group can be bound as a patch-policy / ring
  // smart-group source (no cycle guard - Slice 3 design lock).
  'advisory.applicable_count': 'integer (open applicable rows on host)',
  'advisory.applicable_critical_count': 'integer (severity=critical applicable)',
  'advisory.applicable_high_count': 'integer (severity=high applicable)',
  'advisory.applicable_security_count': 'integer (advisory_class=security applicable)',
  'advisory.unknown_count': 'integer (state=unknown rows on host)',
  'advisory.has_open_advisories': 'true/false',
};
type Condition = { field: string; op: string; value: unknown };
type GroupNode = { op: Op; rules: RuleNode[] };
type RuleNode = GroupNode | Condition;

function isGroup(n: RuleNode): n is GroupNode { return 'rules' in n; }

interface SmartGroup {
  id: number;
  name: string;
  description: string | null;
  rule_json: RuleNode;
  enabled: boolean;
  member_count: number;
  created_at: string;
  updated_at: string;
}

interface MemberSystem { id: number; hostname: string; status: string; ip_address?: string | null }

const emptyRule: GroupNode = { op: 'and', rules: [] };

const defaultValueForType = (t: FieldSpec['type']): unknown => {
  if (t === 'string') return '';
  if (t === 'enum') return [];
  if (t === 'bool') return true;
  return 0;
};

const SmartGroupsPage: React.FC = () => {
  const [groups, setGroups] = useState<SmartGroup[]>([]);
  const [catalog, setCatalog] = useState<FieldSpec[]>([]);
  const [loading, setLoading] = useState(true);

  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<SmartGroup | null>(null);
  const [formName, setFormName] = useState('');
  const [formDesc, setFormDesc] = useState('');
  const [formEnabled, setFormEnabled] = useState(true);
  const [formRule, setFormRule] = useState<GroupNode>(emptyRule);
  const [previewTotal, setPreviewTotal] = useState<number | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);

  const [membersOpen, setMembersOpen] = useState<SmartGroup | null>(null);
  const [members, setMembers] = useState<MemberSystem[]>([]);

  const catalogByField = useMemo(() => {
    const map = new Map<string, FieldSpec>();
    catalog.forEach(f => map.set(f.field, f));
    return map;
  }, [catalog]);

  const fetchGroups = useCallback(async () => {
    try {
      const res = await apiFetch('/api/backend/smart-groups');
      if (res.ok) {
        const data = await res.json();
        setGroups(data.smart_groups || []);
      }
    } finally { setLoading(false); }
  }, []);

  const fetchCatalog = useCallback(async () => {
    const res = await apiFetch('/api/backend/smart-groups/field-catalog');
    if (res.ok) {
      const data = await res.json();
      setCatalog(data.catalog || []);
    }
  }, []);

  useEffect(() => { fetchGroups(); fetchCatalog(); }, [fetchGroups, fetchCatalog]);

  // live preview on rule change
  useEffect(() => {
    if (!modalOpen) return;
    const t = setTimeout(async () => {
      try {
        const res = await apiFetch('/api/backend/smart-groups/preview', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ rule_json: formRule }),
        });
        const data = await res.json();
        if (res.ok) { setPreviewTotal(data.total); setPreviewError(null); }
        else { setPreviewTotal(null); setPreviewError(data.detail || 'Invalid rule'); }
      } catch { setPreviewError('Preview failed'); }
    }, 300);
    return () => clearTimeout(t);
  }, [formRule, modalOpen]);

  const openCreate = () => {
    setEditing(null);
    setFormName(''); setFormDesc(''); setFormEnabled(true); setFormRule(emptyRule);
    setPreviewTotal(null); setPreviewError(null); setModalOpen(true);
  };

  const openEdit = (g: SmartGroup) => {
    setEditing(g);
    setFormName(g.name); setFormDesc(g.description || ''); setFormEnabled(g.enabled);
    setFormRule(isGroup(g.rule_json) ? g.rule_json as GroupNode : { op: 'and', rules: [g.rule_json as RuleNode] });
    setPreviewTotal(null); setPreviewError(null); setModalOpen(true);
  };

  const save = async () => {
    if (!formName.trim()) { toast.error('Name required'); return; }
    if (formRule.rules.length === 0) { toast.error('Add at least one condition'); return; }
    const body: Record<string, unknown> = {
      name: formName, description: formDesc || null,
      rule_json: formRule, enabled: formEnabled,
    };
    const res = editing
      ? await apiFetch(`/api/backend/smart-groups/${editing.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      : await apiFetch('/api/backend/smart-groups', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (res.ok) {
      toast.success(editing ? 'Smart group updated' : 'Smart group created');
      setModalOpen(false); fetchGroups();
    } else {
      const err = await res.json(); toast.error(formatApiError(err, 'Save failed'));
    }
  };

  const remove = async (g: SmartGroup) => {
    if (!confirm(`Delete smart group "${g.name}"?`)) return;
    const res = await apiFetch(`/api/backend/smart-groups/${g.id}`, { method: 'DELETE' });
    if (res.ok) { toast.success('Deleted'); fetchGroups(); } else toast.error('Delete failed');
  };

  const recompute = async (g: SmartGroup) => {
    const res = await apiFetch(`/api/backend/smart-groups/${g.id}/recompute`, { method: 'POST' });
    if (res.ok) { toast.success('Membership recomputed'); fetchGroups(); } else toast.error('Recompute failed');
  };

  const openMembers = async (g: SmartGroup) => {
    setMembersOpen(g);
    const res = await apiFetch(`/api/backend/smart-groups/${g.id}/members`);
    if (res.ok) { const data = await res.json(); setMembers(data.members || []); }
  };

  // --- Rule builder ---------------------------------------------------------

  const updateAtPath = (path: number[], mutator: (node: RuleNode) => RuleNode) => {
    const clone = JSON.parse(JSON.stringify(formRule)) as GroupNode;
    let parent: GroupNode | null = null;
    let current: RuleNode = clone;
    for (let i = 0; i < path.length; i++) {
      parent = current as GroupNode;
      current = (current as GroupNode).rules[path[i]];
    }
    const newNode = mutator(current);
    if (parent === null) setFormRule(newNode as GroupNode);
    else { parent.rules[path[path.length - 1]] = newNode; setFormRule(clone); }
  };

  const deleteAtPath = (path: number[]) => {
    if (path.length === 0) return;
    const clone = JSON.parse(JSON.stringify(formRule)) as GroupNode;
    let parent: GroupNode = clone;
    for (let i = 0; i < path.length - 1; i++) parent = parent.rules[path[i]] as GroupNode;
    parent.rules.splice(path[path.length - 1], 1);
    setFormRule(clone);
  };

  const addCondition = (path: number[]) => {
    const first = catalog[0];
    if (!first) return;
    updateAtPath(path, node => {
      const g = node as GroupNode;
      g.rules.push({ field: first.field, op: first.ops[0], value: defaultValueForType(first.type) });
      return g;
    });
  };

  const addGroup = (path: number[]) => {
    updateAtPath(path, node => {
      const g = node as GroupNode;
      g.rules.push({ op: 'and', rules: [] });
      return g;
    });
  };

  const renderCondition = (c: Condition, path: number[]) => {
    const spec = catalogByField.get(c.field);
    const update = (next: Partial<Condition>) => {
      updateAtPath(path, () => ({ ...c, ...next } as Condition));
    };
    return (
      <div className="flex items-center gap-2 bg-surface-raised/40 border border-border rounded-md px-2 py-1.5">
        <select
          value={c.field}
          onChange={e => {
            const nf = catalogByField.get(e.target.value)!;
            update({ field: nf.field, op: nf.ops[0], value: defaultValueForType(nf.type) });
          }}
          className={`border border-border rounded text-xs px-2 py-1 ${nativeSelectClass}`}
        >
          {catalog.map(f => <option key={f.field} value={f.field}>{f.field}</option>)}
        </select>
        <select
          value={c.op}
          onChange={e => update({ op: e.target.value })}
          className={`border border-border rounded text-xs px-2 py-1 ${nativeSelectClass}`}
        >
          {(spec?.ops || []).map(o => <option key={o} value={o}>{o}</option>)}
        </select>
        {spec?.type === 'string' && (
          <input
            type="text"
            value={String(c.value ?? '')}
            onChange={e => update({ value: e.target.value })}
            className="flex-1 bg-surface-sunken border border-border rounded text-xs text-content px-2 py-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
            placeholder={c.op === 'regex' ? 'POSIX regex' : (FIELD_HINTS[c.field] || 'value')}
            title={FIELD_HINTS[c.field]}
          />
        )}
        {spec?.type === 'enum' && (
          <input
            type="text"
            value={(Array.isArray(c.value) ? (c.value as string[]) : []).join(', ')}
            onChange={e => update({ value: e.target.value.split(',').map(s => s.trim()).filter(Boolean) })}
            className="flex-1 bg-surface-sunken border border-border rounded text-xs text-content px-2 py-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
            placeholder={FIELD_HINTS[c.field] || 'comma,separated,values'}
            title={FIELD_HINTS[c.field]}
          />
        )}
        {spec?.type === 'bool' && (
          <select
            value={String(Boolean(c.value))}
            onChange={e => update({ value: e.target.value === 'true' })}
            className={`border border-border rounded text-xs px-2 py-1 ${nativeSelectClass}`}
          >
            <option value="true">true</option>
            <option value="false">false</option>
          </select>
        )}
        {spec?.type === 'number' && (
          <input
            type="number"
            value={Number(c.value ?? 0)}
            onChange={e => update({ value: Number(e.target.value) })}
            className="w-24 bg-surface-sunken border border-border rounded text-xs text-content px-2 py-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
          />
        )}
        <button onClick={() => deleteAtPath(path)} className="text-content-subtle hover:text-red-400" aria-label="Remove condition">
          <X size={14} />
        </button>
      </div>
    );
  };

  const renderGroup = (g: GroupNode, path: number[]) => {
    const isRoot = path.length === 0;
    return (
      <div className={`border ${isRoot ? 'border-red-900/40' : 'border-border'} rounded-md p-2 space-y-2 bg-surface-sunken/40`}>
        <div className="flex items-center gap-2">
          <select
            value={g.op}
            onChange={e => updateAtPath(path, node => ({ ...(node as GroupNode), op: e.target.value as Op }))}
            className={`border border-border rounded text-xs font-bold uppercase px-2 py-1 ${nativeSelectClass}`}
          >
            <option value="and">AND</option>
            <option value="or">OR</option>
          </select>
          <span className="text-xs text-content-subtle">{g.rules.length} rule{g.rules.length === 1 ? '' : 's'}</span>
          <div className="ml-auto flex gap-1">
            <Button variant="outline" onClick={() => addCondition(path)} icon={<Plus size={12} />}>Condition</Button>
            <Button variant="outline" onClick={() => addGroup(path)} icon={<Plus size={12} />}>Group</Button>
            {!isRoot && (
              <button onClick={() => deleteAtPath(path)} className="text-content-subtle hover:text-red-400 px-1" aria-label="Remove group">
                <X size={14} />
              </button>
            )}
          </div>
        </div>
        <div className="pl-2 space-y-2 border-l-2 border-border">
          {g.rules.length === 0 && <div className="text-xs text-content-subtle italic px-2">Empty group - add a condition or nested group.</div>}
          {g.rules.map((r, i) => (
            <div key={i}>
              {isGroup(r) ? renderGroup(r, [...path, i]) : renderCondition(r, [...path, i])}
            </div>
          ))}
        </div>
      </div>
    );
  };

  // --- Rendering ------------------------------------------------------------

  return (
    <MainLayout>
      <Head><title>Smart Groups - Praxis</title></Head>
      <PageHeader
        title="Smart Groups"
        subtitle="Rule-based dynamic system groups that auto-recompute as the fleet changes."
        actions={<div className="flex items-center gap-2"><Button variant="primary" icon={<Plus size={16} />} onClick={openCreate}>New Smart Group</Button><HelpLink slug="fleet-and-hosts" /></div>}
      />

      <div className="border border-border rounded-lg overflow-hidden">
        <table className="w-full text-sm text-content">
          <thead className="bg-red-900/30 text-content text-xs uppercase">
            <tr>
              <th className="px-4 py-3 text-left">Name</th>
              <th className="px-4 py-3 text-left">Description</th>
              <th className="px-4 py-3 text-center">Members</th>
              <th className="px-4 py-3 text-center">Enabled</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {loading ? (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-content-subtle">Loading...</td></tr>
            ) : groups.length === 0 ? (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-content-subtle">No smart groups yet. Create one to target systems by rule.</td></tr>
            ) : groups.map(g => (
              <tr key={g.id} className="hover:bg-white/[0.03]">
                <td className="px-4 py-3 font-medium flex items-center gap-2"><Filter size={14} className="text-red-400" />{g.name}</td>
                <td className="px-4 py-3 text-content-muted">{g.description || '-'}</td>
                <td className="px-4 py-3 text-center">
                  <button onClick={() => openMembers(g)} className="px-2 py-0.5 bg-border hover:bg-border-strong rounded text-xs">
                    {g.member_count} <ChevronRight size={12} className="inline" />
                  </button>
                </td>
                <td className="px-4 py-3 text-center">
                  <span className={`px-2 py-0.5 rounded text-xs ${g.enabled ? 'bg-green-900 text-green-200' : 'bg-zinc-800 text-zinc-400'}`}>
                    {g.enabled ? 'on' : 'off'}
                  </span>
                </td>
                <td className="px-4 py-3 text-right">
                  <div className="flex justify-end gap-2">
                    <button onClick={() => recompute(g)} className="p-1 text-content-muted hover:text-amber-400" title="Recompute membership"><RefreshCw size={16} /></button>
                    <button onClick={() => openEdit(g)} className="p-1 text-content-muted hover:text-content" title="Edit"><Pencil size={16} /></button>
                    <button onClick={() => remove(g)} className="p-1 text-content-muted hover:text-red-400" title="Delete"><Trash2 size={16} /></button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Editor modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-surface/70">
          <div className="bg-surface-overlay border border-border rounded-lg w-full max-w-3xl p-6 space-y-4 max-h-[92vh] overflow-y-auto">
            <h2 className="text-lg font-bold text-content">{editing ? 'Edit Smart Group' : 'Create Smart Group'}</h2>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-sm text-content-muted mb-1">Name</label>
                <input value={formName} onChange={e => setFormName(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-sunken border border-border rounded text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                  placeholder="e.g. Production Ubuntu Servers" />
              </div>
              <div>
                <label className="block text-sm text-content-muted mb-1">Description (optional)</label>
                <input value={formDesc} onChange={e => setFormDesc(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-sunken border border-border rounded text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong" />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm text-content-muted">Rule</label>
                <div className="text-xs">
                  {previewError ? (
                    <span className="text-red-400">{previewError}</span>
                  ) : previewTotal !== null ? (
                    <span className="text-green-400">matches <strong>{previewTotal}</strong> system{previewTotal === 1 ? '' : 's'}</span>
                  ) : null}
                </div>
              </div>
              {renderGroup(formRule, [])}
            </div>

            <div className="flex items-center gap-2">
              <input id="sg-enabled" type="checkbox" checked={formEnabled}
                onChange={e => setFormEnabled(e.target.checked)} className="accent-red-600" />
              <label htmlFor="sg-enabled" className="text-sm text-content">Enabled</label>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <Button variant="outline" onClick={() => setModalOpen(false)}>Cancel</Button>
              <Button variant="primary" onClick={save} disabled={!formName || formRule.rules.length === 0}>
                {editing ? 'Update' : 'Create'}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Members drawer */}
      {membersOpen && (
        <div className="fixed inset-0 z-40 flex justify-end bg-surface/70" onClick={() => setMembersOpen(null)}>
          <div className="bg-surface-overlay border-l border-border w-full max-w-md h-full overflow-y-auto p-5 space-y-3" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-content flex items-center gap-2"><UsersIcon size={18} /> Members · {membersOpen.name}</h3>
              <button onClick={() => setMembersOpen(null)} className="text-content-subtle hover:text-content"><X size={18} /></button>
            </div>
            <div className="text-xs text-content-subtle">{members.length} member{members.length === 1 ? '' : 's'}</div>
            <div className="border border-border rounded divide-y divide-border/70">
              {members.length === 0 ? (
                <div className="p-4 text-sm text-content-subtle">No systems match this rule right now.</div>
              ) : members.map(m => (
                <div key={m.id} className="p-3 flex items-center justify-between">
                  <div>
                    <div className="text-sm text-content font-medium">{m.hostname}</div>
                    <div className="text-xs text-content-subtle">{m.ip_address || ''}</div>
                  </div>
                  <StatusBadge status={m.status} />
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </MainLayout>
  );
};

export default SmartGroupsPage;
