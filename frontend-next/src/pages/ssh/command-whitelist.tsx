import React, { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import MainLayout from '../../components/MainLayout';
import { apiFetch, formatApiError } from '@/utils/api';
import { Plus, Pencil, Trash2, Search, ToggleLeft, ToggleRight } from 'lucide-react';
import Head from 'next/head';
import { PageHeader, Button, Card, CardBody, ConfirmModal, EmptyState, SkeletonTable } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { humanizeLabel } from '@/utils/humanize';

interface DistroMapping {
  id?: number;
  distro_id: number;
  distro_name?: string;
  distro_version?: string;
  distro_version_pattern: string | null;
  command_override: string | null;
  is_supported: boolean;
  notes: string | null;
}

interface WhitelistEntry {
  id: number;
  name: string;
  description: string | null;
  command_pattern: string;
  is_regex: boolean;
  is_active: boolean;
  risk_level: string;
  category: string;
  requires_sudo: boolean;
  requires_approval: boolean;
  required_approvals: number;
  timeout_seconds: number;
  created_by: number;
  created_at: string;
  updated_at: string;
  distro_mappings: DistroMapping[];
}

interface DistroOption {
  id: number;
  name: string;
  version: string;
}

const RISK_COLORS: Record<string, string> = {
  low: 'bg-green-900/50 text-green-400 border-green-700',
  medium: 'bg-yellow-900/50 text-yellow-400 border-yellow-700',
  high: 'bg-orange-900/50 text-orange-400 border-orange-700',
  critical: 'bg-red-900/50 text-red-400 border-red-700',
};

const CATEGORIES = [
  'package_management', 'system_info', 'file_operations', 'network',
  'service_management', 'monitoring', 'security', 'custom',
];

const RISK_LEVELS = ['low', 'medium', 'high', 'critical'];

const CommandWhitelistPage: React.FC = () => {
  const [entries, setEntries] = useState<WhitelistEntry[]>([]);
  const [distros, setDistros] = useState<DistroOption[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<WhitelistEntry | null>(null);
  const [filterCategory, setFilterCategory] = useState('');
  const [filterRisk, setFilterRisk] = useState('');
  const [filterActive, setFilterActive] = useState('');

  // Delete confirm state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleteTargetId, setDeleteTargetId] = useState<number | null>(null);

  // Pattern tester
  const [testCommand, setTestCommand] = useState('');
  const [testResult, setTestResult] = useState<{allowed: boolean; whitelist_matches: {name: string; risk_level: string}[]; rule_matches: {name: string; severity: string}[]} | null>(null);
  const [testing, setTesting] = useState(false);

  // Form state
  const [formName, setFormName] = useState('');
  const [formDescription, setFormDescription] = useState('');
  const [formPattern, setFormPattern] = useState('');
  const [formIsRegex, setFormIsRegex] = useState(false);
  const [formRiskLevel, setFormRiskLevel] = useState('low');
  const [formCategory, setFormCategory] = useState('system_info');
  const [formRequiresSudo, setFormRequiresSudo] = useState(false);
  const [formRequiresApproval, setFormRequiresApproval] = useState(false);
  const [formRequiredApprovals, setFormRequiredApprovals] = useState(1);
  const [formTimeout, setFormTimeout] = useState(30);
  const [formDistroMappings, setFormDistroMappings] = useState<DistroMapping[]>([]);

  const loadData = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (filterCategory) params.set('category', filterCategory);
      if (filterRisk) params.set('risk_level', filterRisk);
      if (filterActive) params.set('is_active', filterActive);
      const qs = params.toString();

      const [entriesRes, distrosRes] = await Promise.all([
        apiFetch(`/api/backend/command-whitelist/whitelist${qs ? `?${qs}` : ''}`),
        apiFetch('/api/backend/command-whitelist/distros'),
      ]);
      if (entriesRes.ok) {
        const data = await entriesRes.json();
        setEntries(data.entries);
      }
      if (distrosRes.ok) {
        const data = await distrosRes.json();
        setDistros(data.distros);
      }
    } catch {
      toast.error('Failed to load whitelist data');
    } finally {
      setLoading(false);
    }
  }, [filterCategory, filterRisk, filterActive]);

  useEffect(() => { loadData(); }, [loadData]);

  const openCreate = () => {
    setEditing(null);
    setFormName(''); setFormDescription(''); setFormPattern('');
    setFormIsRegex(false); setFormRiskLevel('low'); setFormCategory('system_info');
    setFormRequiresSudo(false); setFormRequiresApproval(false); setFormRequiredApprovals(1); setFormTimeout(30); setFormDistroMappings([]);
    setModalOpen(true);
  };

  const openEdit = (entry: WhitelistEntry) => {
    setEditing(entry);
    setFormName(entry.name); setFormDescription(entry.description || '');
    setFormPattern(entry.command_pattern); setFormIsRegex(entry.is_regex);
    setFormRiskLevel(entry.risk_level); setFormCategory(entry.category);
    setFormRequiresSudo(entry.requires_sudo); setFormRequiresApproval(entry.requires_approval); setFormRequiredApprovals(entry.required_approvals || 1); setFormTimeout(entry.timeout_seconds);
    setFormDistroMappings(entry.distro_mappings.map(m => ({ ...m })));
    setModalOpen(true);
  };

  const handleSave = async () => {
    const body = {
      name: formName, description: formDescription || null,
      command_pattern: formPattern, is_regex: formIsRegex,
      risk_level: formRiskLevel, category: formCategory,
      requires_sudo: formRequiresSudo, requires_approval: formRequiresApproval, required_approvals: formRequiresApproval ? formRequiredApprovals : 1, timeout_seconds: formTimeout,
      distro_mappings: formDistroMappings.map(m => ({
        distro_id: m.distro_id, distro_version_pattern: m.distro_version_pattern,
        command_override: m.command_override, is_supported: m.is_supported, notes: m.notes,
      })),
    };
    try {
      const res = editing
        ? await apiFetch(`/api/backend/command-whitelist/whitelist/${editing.id}`, { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) })
        : await apiFetch('/api/backend/command-whitelist/whitelist', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
      if (!res.ok) { const e = await res.json(); throw new Error(formatApiError(e, 'Failed')); }
      toast.success(editing ? 'Entry updated' : 'Entry created');
      setModalOpen(false);
      loadData();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to save');
    }
  };

  const handleDelete = async (id: number) => {
    try {
      const res = await apiFetch(`/api/backend/command-whitelist/whitelist/${id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error('Failed to delete');
      toast.success('Entry deleted');
      loadData();
    } catch { toast.error('Failed to delete'); }
    setShowDeleteConfirm(false);
    setDeleteTargetId(null);
  };

  const handleToggle = async (entry: WhitelistEntry) => {
    try {
      const res = await apiFetch(`/api/backend/command-whitelist/whitelist/${entry.id}`, {
        method: 'PUT', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ is_active: !entry.is_active }),
      });
      if (!res.ok) throw new Error('Failed');
      loadData();
    } catch { toast.error('Failed to toggle'); }
  };

  const handleTest = async () => {
    if (!testCommand.trim()) return;
    setTesting(true);
    try {
      const res = await apiFetch('/api/backend/command-whitelist/test-pattern', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ command: testCommand }),
      });
      if (res.ok) setTestResult(await res.json());
    } catch { toast.error('Test failed'); }
    finally { setTesting(false); }
  };

  const addDistroMapping = () => {
    if (distros.length === 0) return;
    setFormDistroMappings([...formDistroMappings, {
      distro_id: distros[0].id, distro_version_pattern: null,
      command_override: null, is_supported: true, notes: null,
    }]);
  };

  const removeDistroMapping = (idx: number) => {
    setFormDistroMappings(formDistroMappings.filter((_, i) => i !== idx));
  };

  const updateDistroMapping = (idx: number, field: string, value: string | number | boolean | null) => {
    setFormDistroMappings(formDistroMappings.map((m, i) => i === idx ? { ...m, [field]: value } : m));
  };

  if (loading) {
    return <MainLayout>
        <Head>
          <title>Command Whitelist | Praxis</title>
        </Head><SkeletonTable rows={5} cols={7} /></MainLayout>;
  }

  return (
    <MainLayout>
      <Head>
        <title>Command Whitelist | Praxis</title>
      </Head>
        <PageHeader
          title="Command Whitelist"
          actions={
            <div className="flex items-center gap-2">
              <Button variant="primary" icon={<Plus size={16} />} onClick={openCreate}>
                Add Entry
              </Button>
              <HelpLink slug="ssh-and-security" />
            </div>
          }
        />

        {/* Pattern Tester */}
        <Card className="mb-6">
          <CardBody>
            <div className="flex items-center gap-2 mb-3">
              <Search size={18} className="text-gray-400" />
              <span className="text-sm font-medium text-gray-300">Pattern Tester</span>
            </div>
            <div className="flex gap-2">
              <input value={testCommand} onChange={(e) => setTestCommand(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleTest()}
                placeholder="Enter a command to test (e.g. apt-get install nginx)"
                className="flex-1 bg-white/[0.02] border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-red-500 focus:outline-none" />
              <Button variant="outline" onClick={handleTest} disabled={testing}>
                {testing ? 'Testing...' : 'Test'}
              </Button>
            </div>
            {testResult && (
              <div className="mt-3 text-sm">
                <div className={`font-medium ${testResult.allowed ? 'text-green-400' : 'text-red-400'}`}>
                  {testResult.allowed ? 'ALLOWED' : 'DENIED'}
                </div>
                {testResult.whitelist_matches.length > 0 && (
                  <div className="text-gray-400 mt-1">Whitelist matches: {testResult.whitelist_matches.map(m => m.name).join(', ')}</div>
                )}
                {testResult.rule_matches.length > 0 && (
                  <div className="text-yellow-400 mt-1">Rule triggers: {testResult.rule_matches.map(r => `${r.name} (${r.severity})`).join(', ')}</div>
                )}
                {testResult.whitelist_matches.length === 0 && <div className="text-gray-600 mt-1">No whitelist match found</div>}
              </div>
            )}
          </CardBody>
        </Card>

        {/* Filters */}
        <div className="flex gap-4 mb-4">
          <select value={filterCategory} onChange={(e) => setFilterCategory(e.target.value)}
            className="bg-white/[0.02] border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200">
            <option value="">All Categories</option>
            {CATEGORIES.map(c => <option key={c} value={c}>{humanizeLabel(c)}</option>)}
          </select>
          <select value={filterRisk} onChange={(e) => setFilterRisk(e.target.value)}
            className="bg-white/[0.02] border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200">
            <option value="">All Risk Levels</option>
            {RISK_LEVELS.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
          <select value={filterActive} onChange={(e) => setFilterActive(e.target.value)}
            className="bg-white/[0.02] border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200">
            <option value="">All Status</option>
            <option value="true">Active</option>
            <option value="false">Inactive</option>
          </select>
        </div>

        {/* Table */}
        <Card>
          <CardBody className="p-0">
            <table className="w-full text-sm">
              <thead className="bg-gray-950">
                <tr className="text-left text-gray-400 border-b border-gray-800">
                  <th scope="col" className="px-4 py-3">Name</th>
                  <th scope="col" className="px-4 py-3">Pattern</th>
                  <th scope="col" className="px-4 py-3">Category</th>
                  <th scope="col" className="px-4 py-3">Risk</th>
                  <th scope="col" className="px-4 py-3">Status</th>
                  <th scope="col" className="px-4 py-3">Distros</th>
                  <th scope="col" className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <tr key={entry.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                    <td className="px-4 py-3">
                      <div className="font-medium text-gray-100">{entry.name}</div>
                      {entry.description && <div className="text-xs text-gray-600 mt-0.5">{entry.description}</div>}
                    </td>
                    <td className="px-4 py-3">
                      <code className="text-xs bg-gray-950 px-2 py-1 rounded text-gray-300">
                        {entry.command_pattern}
                      </code>
                      {entry.is_regex && <span className="ml-2 text-xs text-slate-300">regex</span>}
                      {entry.requires_sudo && <span className="ml-2 text-xs text-yellow-500">sudo</span>}
                      {entry.requires_approval && <span className="ml-2 text-xs text-purple-400">approval{entry.required_approvals > 1 ? ` × ${entry.required_approvals}` : ''}</span>}
                    </td>
                    <td className="px-4 py-3 text-gray-400">{humanizeLabel(entry.category)}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded border ${RISK_COLORS[entry.risk_level] || ''}`}>
                        {entry.risk_level}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <button onClick={() => handleToggle(entry)} title={entry.is_active ? 'Active' : 'Inactive'}>
                        {entry.is_active
                          ? <ToggleRight size={20} className="text-green-400" />
                          : <ToggleLeft size={20} className="text-gray-600" />}
                      </button>
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">
                      {entry.distro_mappings.length > 0
                        ? entry.distro_mappings.map(m => m.distro_name).join(', ')
                        : <span className="text-gray-600">All</span>}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button onClick={() => openEdit(entry)} className="text-gray-400 hover:text-gray-100 mr-3"><Pencil size={14} /></button>
                      <button onClick={() => { setDeleteTargetId(entry.id); setShowDeleteConfirm(true); }} className="text-gray-400 hover:text-red-400"><Trash2 size={14} /></button>
                    </td>
                  </tr>
                ))}
                {entries.length === 0 && (
                  <tr><td colSpan={7}><EmptyState title="No whitelist entries found" /></td></tr>
                )}
              </tbody>
            </table>
          </CardBody>
        </Card>

        {/* Modal */}
        {modalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#0c0c0f]/60">
            <div className="bg-gray-950 border border-gray-800 rounded-lg w-full max-w-2xl max-h-[85vh] overflow-y-auto p-6">
              <h2 className="text-lg font-semibold text-gray-100 mb-4">{editing ? 'Edit Entry' : 'New Whitelist Entry'}</h2>

              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Name</label>
                  <input value={formName} onChange={(e) => setFormName(e.target.value)}
                    className="w-full bg-white/[0.02] border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-red-500 focus:outline-none" />
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Category</label>
                  <select value={formCategory} onChange={(e) => setFormCategory(e.target.value)}
                    className="w-full bg-white/[0.02] border border-gray-700 rounded px-3 py-2 text-sm text-gray-200">
                    {CATEGORIES.map(c => <option key={c} value={c}>{humanizeLabel(c)}</option>)}
                  </select>
                </div>
              </div>

              <div className="mb-4">
                <label className="block text-xs text-gray-400 mb-1">Description</label>
                <input value={formDescription} onChange={(e) => setFormDescription(e.target.value)}
                  className="w-full bg-white/[0.02] border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-red-500 focus:outline-none" />
              </div>

              <div className="mb-4">
                <label className="block text-xs text-gray-400 mb-1">Command Pattern</label>
                <input value={formPattern} onChange={(e) => setFormPattern(e.target.value)}
                  placeholder="e.g. apt-get install * or ^apt-get\s+install\s+\S+$"
                  className="w-full bg-white/[0.02] border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 font-mono focus:border-red-500 focus:outline-none" />
              </div>

              <div className="grid grid-cols-3 gap-4 mb-4">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Risk Level</label>
                  <select value={formRiskLevel} onChange={(e) => setFormRiskLevel(e.target.value)}
                    className="w-full bg-white/[0.02] border border-gray-700 rounded px-3 py-2 text-sm text-gray-200">
                    {RISK_LEVELS.map(r => <option key={r} value={r}>{r}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Timeout (seconds)</label>
                  <input type="number" value={formTimeout} onChange={(e) => setFormTimeout(parseInt(e.target.value) || 30)}
                    min={1} max={3600}
                    className="w-full bg-white/[0.02] border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-red-500 focus:outline-none" />
                </div>
                <div className="flex flex-col justify-end gap-2">
                  <label className="flex items-center gap-2 text-sm text-gray-300">
                    <input type="checkbox" checked={formIsRegex} onChange={(e) => setFormIsRegex(e.target.checked)}
                      className="rounded border-gray-700" /> Regex pattern
                  </label>
                  <label className="flex items-center gap-2 text-sm text-gray-300">
                    <input type="checkbox" checked={formRequiresSudo} onChange={(e) => setFormRequiresSudo(e.target.checked)}
                      className="rounded border-gray-700" /> Requires sudo
                  </label>
                  <label className="flex items-center gap-2 text-sm text-gray-300">
                    <input type="checkbox" checked={formRequiresApproval} onChange={(e) => setFormRequiresApproval(e.target.checked)}
                      className="rounded border-gray-700" /> Requires approval
                  </label>
                  {formRequiresApproval && (
                    <label className="flex items-center gap-2 text-sm text-gray-300 pl-6">
                      <span className="text-xs text-gray-400">Required approvals</span>
                      <input
                        type="number"
                        min={1}
                        max={10}
                        value={formRequiredApprovals}
                        onChange={(e) => setFormRequiredApprovals(Math.max(1, parseInt(e.target.value) || 1))}
                        className="w-16 bg-white/[0.02] border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 focus:border-red-500 focus:outline-none"
                      />
                      <span className="text-xs text-gray-500">distinct admins</span>
                    </label>
                  )}
                </div>
              </div>

              {/* Distro Mappings */}
              <div className="mb-4">
                <div className="flex items-center justify-between mb-2">
                  <label className="text-xs text-gray-400">Distribution Support</label>
                  <button onClick={addDistroMapping} className="text-xs text-red-400 hover:text-red-300">+ Add Distribution</button>
                </div>
                {formDistroMappings.length === 0 && (
                  <div className="text-xs text-gray-600 bg-gray-950 rounded p-3">No distribution restrictions -- command applies to all distributions.</div>
                )}
                {formDistroMappings.map((m, idx) => (
                  <div key={idx} className="flex gap-2 items-start mb-2 bg-gray-950 rounded p-3">
                    <select value={m.distro_id} onChange={(e) => updateDistroMapping(idx, 'distro_id', parseInt(e.target.value))}
                      className="bg-white/[0.02] border border-gray-700 rounded px-2 py-1 text-xs text-gray-200">
                      {distros.map(d => <option key={d.id} value={d.id}>{d.name} {d.version}</option>)}
                    </select>
                    <input value={m.command_override || ''} onChange={(e) => updateDistroMapping(idx, 'command_override', e.target.value || null)}
                      placeholder="Command override" className="flex-1 bg-white/[0.02] border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono" />
                    <button onClick={() => removeDistroMapping(idx)} className="text-gray-600 hover:text-red-400 mt-0.5"><Trash2 size={12} /></button>
                  </div>
                ))}
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-gray-800">
                <Button variant="ghost" onClick={() => setModalOpen(false)}>Cancel</Button>
                <Button variant="primary" onClick={handleSave} disabled={!formName || !formPattern}>
                  {editing ? 'Update' : 'Create'}
                </Button>
              </div>
            </div>
          </div>
        )}

        <ConfirmModal
          open={showDeleteConfirm}
          onClose={() => { setShowDeleteConfirm(false); setDeleteTargetId(null); }}
          onConfirm={() => deleteTargetId && handleDelete(deleteTargetId)}
          title="Delete Whitelist Entry"
          message="Delete this whitelist entry?"
          confirmLabel="Delete"
          variant="danger"
        />
    </MainLayout>
  );
};

export default CommandWhitelistPage;
