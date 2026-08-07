import React, { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import MainLayout from '../../components/MainLayout';
import { apiFetch, formatApiError } from '@/utils/api';
import { Plus, Pencil, Trash2, Search, ToggleLeft, ToggleRight } from 'lucide-react';
import Head from 'next/head';
import { PageHeader, Button, Card, CardBody, ConfirmModal, EmptyState, SkeletonTable } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { humanizeLabel } from '@/utils/humanize';

interface ValidationRule {
  id: number;
  name: string;
  description: string | null;
  validation_type: string;
  pattern: string;
  is_regex: boolean;
  is_active: boolean;
  severity: string;
  error_message: string | null;
  created_by: number;
  created_at: string;
  updated_at: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  info: 'bg-slate-900/50 text-slate-300 border-slate-700',
  warning: 'bg-yellow-900/50 text-yellow-400 border-yellow-700',
  error: 'bg-orange-900/50 text-orange-400 border-orange-700',
  critical: 'bg-red-900/50 text-red-400 border-red-700',
};

const SEVERITIES = ['info', 'warning', 'error', 'critical'];
const VALIDATION_TYPES = ['pattern', 'blacklist', 'parameter_check'];

const ValidationRulesPage: React.FC = () => {
  const [rules, setRules] = useState<ValidationRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<ValidationRule | null>(null);
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterType, setFilterType] = useState('');
  const [filterActive, setFilterActive] = useState('');

  // Delete confirm state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleteTargetId, setDeleteTargetId] = useState<number | null>(null);

  // Pattern tester
  const [testCommand, setTestCommand] = useState('');
  const [testResult, setTestResult] = useState<{allowed: boolean; whitelist_matches: {name: string}[]; rule_matches: {name: string; severity: string}[]} | null>(null);
  const [testing, setTesting] = useState(false);

  // Form
  const [formName, setFormName] = useState('');
  const [formDescription, setFormDescription] = useState('');
  const [formValidationType, setFormValidationType] = useState('blacklist');
  const [formPattern, setFormPattern] = useState('');
  const [formIsRegex, setFormIsRegex] = useState(false);
  const [formSeverity, setFormSeverity] = useState('error');
  const [formErrorMessage, setFormErrorMessage] = useState('');

  const loadData = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (filterSeverity) params.set('severity', filterSeverity);
      if (filterType) params.set('validation_type', filterType);
      if (filterActive) params.set('is_active', filterActive);
      const qs = params.toString();

      const res = await apiFetch(`/api/backend/command-whitelist/validation-rules${qs ? `?${qs}` : ''}`);
      if (res.ok) {
        const data = await res.json();
        setRules(data.rules);
      }
    } catch {
      toast.error('Failed to load validation rules');
    } finally {
      setLoading(false);
    }
  }, [filterSeverity, filterType, filterActive]);

  useEffect(() => { loadData(); }, [loadData]);

  const openCreate = () => {
    setEditing(null);
    setFormName(''); setFormDescription(''); setFormValidationType('blacklist');
    setFormPattern(''); setFormIsRegex(false); setFormSeverity('error'); setFormErrorMessage('');
    setModalOpen(true);
  };

  const openEdit = (rule: ValidationRule) => {
    setEditing(rule);
    setFormName(rule.name); setFormDescription(rule.description || '');
    setFormValidationType(rule.validation_type); setFormPattern(rule.pattern);
    setFormIsRegex(rule.is_regex); setFormSeverity(rule.severity);
    setFormErrorMessage(rule.error_message || '');
    setModalOpen(true);
  };

  const handleSave = async () => {
    const body = {
      name: formName, description: formDescription || null,
      validation_type: formValidationType, pattern: formPattern,
      is_regex: formIsRegex, severity: formSeverity,
      error_message: formErrorMessage || null,
    };
    try {
      const res = editing
        ? await apiFetch(`/api/backend/command-whitelist/validation-rules/${editing.id}`, { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) })
        : await apiFetch('/api/backend/command-whitelist/validation-rules', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
      if (!res.ok) { const e = await res.json(); throw new Error(formatApiError(e, 'Failed')); }
      toast.success(editing ? 'Rule updated' : 'Rule created');
      setModalOpen(false);
      loadData();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to save');
    }
  };

  const handleDelete = async (id: number) => {
    try {
      const res = await apiFetch(`/api/backend/command-whitelist/validation-rules/${id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error('Failed');
      toast.success('Rule deleted');
      loadData();
    } catch { toast.error('Failed to delete'); }
    setShowDeleteConfirm(false);
    setDeleteTargetId(null);
  };

  const handleToggle = async (rule: ValidationRule) => {
    try {
      const res = await apiFetch(`/api/backend/command-whitelist/validation-rules/${rule.id}`, {
        method: 'PUT', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ is_active: !rule.is_active }),
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

  if (loading) {
    return <MainLayout>
        <Head>
          <title>Validation Rules | Praxis</title>
        </Head><SkeletonTable rows={5} cols={6} /></MainLayout>;
  }

  return (
    <MainLayout>
      <Head>
        <title>Validation Rules | Praxis</title>
      </Head>
        <PageHeader
          title="Validation Rules"
          actions={
            <div className="flex items-center gap-2">
              <Button variant="primary" icon={<Plus size={16} />} onClick={openCreate}>
                Add Rule
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
              <span className="text-sm font-medium text-gray-300">Rule Tester</span>
            </div>
            <div className="flex gap-2">
              <input value={testCommand} onChange={(e) => setTestCommand(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleTest()}
                placeholder="Enter a command to test against rules (e.g. rm -rf /)"
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
                {testResult.rule_matches.length > 0 && (
                  <div className="text-yellow-400 mt-1">Triggered rules: {testResult.rule_matches.map(r => `${r.name} (${r.severity})`).join(', ')}</div>
                )}
                {testResult.rule_matches.length === 0 && <div className="text-gray-600 mt-1">No rules triggered</div>}
              </div>
            )}
          </CardBody>
        </Card>

        {/* Filters */}
        <div className="flex gap-4 mb-4">
          <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-white/[0.02] border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200">
            <option value="">All Severities</option>
            {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={filterType} onChange={(e) => setFilterType(e.target.value)}
            className="bg-white/[0.02] border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200">
            <option value="">All Types</option>
            {VALIDATION_TYPES.map(t => <option key={t} value={t}>{humanizeLabel(t)}</option>)}
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
            <div className="overflow-x-auto">
            <table className="w-full min-w-[48rem] text-sm">
              <thead className="bg-gray-950">
                <tr className="text-left text-gray-400 border-b border-gray-800">
                  <th scope="col" className="px-4 py-3">Name</th>
                  <th scope="col" className="px-4 py-3">Pattern</th>
                  <th scope="col" className="px-4 py-3">Type</th>
                  <th scope="col" className="px-4 py-3">Severity</th>
                  <th scope="col" className="px-4 py-3">Status</th>
                  <th scope="col" className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                    <td className="px-4 py-3">
                      <div className="font-medium text-gray-100">{rule.name}</div>
                      {rule.description && <div className="text-xs text-gray-600 mt-0.5">{rule.description}</div>}
                      {rule.error_message && <div className="text-xs text-red-400/70 mt-0.5">{rule.error_message}</div>}
                    </td>
                    <td className="px-4 py-3">
                      <code className="text-xs bg-gray-950 px-2 py-1 rounded text-gray-300">{rule.pattern}</code>
                      {rule.is_regex && <span className="ml-2 text-xs text-slate-300">regex</span>}
                    </td>
                    <td className="px-4 py-3 text-gray-400">{humanizeLabel(rule.validation_type)}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded border ${SEVERITY_COLORS[rule.severity] || ''}`}>
                        {rule.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <button onClick={() => handleToggle(rule)} title={rule.is_active ? 'Active' : 'Inactive'}>
                        {rule.is_active
                          ? <ToggleRight size={20} className="text-green-400" />
                          : <ToggleLeft size={20} className="text-gray-600" />}
                      </button>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button onClick={() => openEdit(rule)} className="text-gray-400 hover:text-gray-100 mr-3"><Pencil size={14} /></button>
                      <button onClick={() => { setDeleteTargetId(rule.id); setShowDeleteConfirm(true); }} className="text-gray-400 hover:text-red-400"><Trash2 size={14} /></button>
                    </td>
                  </tr>
                ))}
                {rules.length === 0 && (
                  <tr><td colSpan={6}><EmptyState title="No validation rules found" /></td></tr>
                )}
              </tbody>
            </table>
            </div>
          </CardBody>
        </Card>

        {/* Modal */}
        {modalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#0c0c0f]/60">
            <div className="bg-gray-950 border border-gray-800 rounded-lg w-full max-w-lg p-6">
              <h2 className="text-lg font-semibold text-gray-100 mb-4">{editing ? 'Edit Rule' : 'New Validation Rule'}</h2>

              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Name</label>
                  <input value={formName} onChange={(e) => setFormName(e.target.value)}
                    className="w-full bg-white/[0.02] border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-red-500 focus:outline-none" />
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Type</label>
                  <select value={formValidationType} onChange={(e) => setFormValidationType(e.target.value)}
                    className="w-full bg-white/[0.02] border border-gray-700 rounded px-3 py-2 text-sm text-gray-200">
                    {VALIDATION_TYPES.map(t => <option key={t} value={t}>{humanizeLabel(t)}</option>)}
                  </select>
                </div>
              </div>

              <div className="mb-4">
                <label className="block text-xs text-gray-400 mb-1">Description</label>
                <input value={formDescription} onChange={(e) => setFormDescription(e.target.value)}
                  className="w-full bg-white/[0.02] border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-red-500 focus:outline-none" />
              </div>

              <div className="mb-4">
                <label className="block text-xs text-gray-400 mb-1">Pattern</label>
                <input value={formPattern} onChange={(e) => setFormPattern(e.target.value)}
                  placeholder="e.g. rm -rf / or ^rm\s+-rf\s+/"
                  className="w-full bg-white/[0.02] border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 font-mono focus:border-red-500 focus:outline-none" />
              </div>

              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Severity</label>
                  <select value={formSeverity} onChange={(e) => setFormSeverity(e.target.value)}
                    className="w-full bg-white/[0.02] border border-gray-700 rounded px-3 py-2 text-sm text-gray-200">
                    {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
                <div className="flex items-end">
                  <label className="flex items-center gap-2 text-sm text-gray-300 pb-2">
                    <input type="checkbox" checked={formIsRegex} onChange={(e) => setFormIsRegex(e.target.checked)}
                      className="rounded border-gray-700" /> Regex pattern
                  </label>
                </div>
              </div>

              <div className="mb-4">
                <label className="block text-xs text-gray-400 mb-1">Error Message (shown when rule triggers)</label>
                <input value={formErrorMessage} onChange={(e) => setFormErrorMessage(e.target.value)}
                  placeholder="e.g. This command is blocked for safety reasons"
                  className="w-full bg-white/[0.02] border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-red-500 focus:outline-none" />
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
          title="Delete Validation Rule"
          message="Delete this validation rule?"
          confirmLabel="Delete"
          variant="danger"
        />
    </MainLayout>
  );
};

export default ValidationRulesPage;
