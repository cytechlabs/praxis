import React, { useEffect, useState, useCallback } from 'react';
import { toast } from 'sonner';
import { apiFetch, formatApiError } from '@/utils/api';
import { Bell, Plus, Pencil, Trash2, TestTube, ChevronDown, ChevronUp, CheckCircle, XCircle, Clock, RefreshCw, AlertTriangle, Key } from 'lucide-react';
import { Button } from '@/components/ui';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { humanizeLabel } from '@/utils/humanize';

interface AlertConfig {
  id: number;
  name: string;
  alert_type: string;
  destination: string;
  events: string[];
  enabled: boolean;
  has_secret: boolean;
  scope_smart_group_id: number | null;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

interface SmartGroupOption { id: number; name: string; member_count: number }

interface AlertHistoryItem {
  id: number;
  alert_config_id: number;
  event_type: string;
  message: string;
  sent_at: string;
  status: string;
  error_message: string | null;
  response_code: number | null;
  attempt_count: number;
  next_retry_at: string | null;
  last_attempted_at: string | null;
  created_at: string;
}

const ALL_EVENT_TYPES = [
  'job_completed', 'job_failed', 'job_cancelled', 'job_rollback',
  'system_unreachable', 'system_recovered',
  'security_updates', 'host_eol_approaching', 'host_eol_reached', 'host_key_changed',
  'package_scan_complete', 'credential_change',
  'system_added', 'system_removed',
  'bulk_operation_complete',
  'audit_event', 'fleet_operation_complete',
];

const AlertConfigTab: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const [configs, setConfigs] = useState<AlertConfig[]>([]);
  const [history, setHistory] = useState<AlertHistoryItem[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editingConfig, setEditingConfig] = useState<AlertConfig | null>(null);

  // Form state
  const [formName, setFormName] = useState('');
  const [formType, setFormType] = useState<'slack' | 'webhook'>('slack');
  const [formDestination, setFormDestination] = useState('');
  const [formEvents, setFormEvents] = useState<string[]>([]);
  const [formEnabled, setFormEnabled] = useState(true);
  const [formSecret, setFormSecret] = useState('');
  const [formClearSecret, setFormClearSecret] = useState(false);
  const [formScopeId, setFormScopeId] = useState<number | ''>('');
  const [smartGroups, setSmartGroups] = useState<SmartGroupOption[]>([]);

  const fetchConfigs = useCallback(async () => {
    try {
      const res = await apiFetch('/api/backend/alerts');
      if (res.ok) {
        const data = await res.json();
        setConfigs(data.configs || []);
      }
    } catch (e) {
      console.error('Failed to fetch alert configs', e);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchHistory = useCallback(async () => {
    try {
      const res = await apiFetch('/api/backend/alerts/history?limit=50');
      if (res.ok) {
        const data = await res.json();
        setHistory(data.history || []);
      }
    } catch (e) {
      console.error('Failed to fetch alert history', e);
    }
  }, []);

  useEffect(() => {
    fetchConfigs();
  }, [fetchConfigs]);

  useEffect(() => {
    (async () => {
      try {
        const res = await apiFetch('/api/backend/smart-groups');
        if (res.ok) {
          const data = await res.json();
          setSmartGroups((data.smart_groups || []).map((g: SmartGroupOption) => ({ id: g.id, name: g.name, member_count: g.member_count })));
        }
      } catch { /* ignore */ }
    })();
  }, []);

  useEffect(() => {
    if (showHistory) fetchHistory();
  }, [showHistory, fetchHistory]);

  const openCreateModal = () => {
    setEditingConfig(null);
    setFormName('');
    setFormType('slack');
    setFormDestination('');
    setFormEvents([]);
    setFormEnabled(true);
    setFormSecret('');
    setFormClearSecret(false);
    setFormScopeId('');
    setModalOpen(true);
  };

  const openEditModal = (config: AlertConfig) => {
    setEditingConfig(config);
    setFormName(config.name);
    setFormType(config.alert_type as 'slack' | 'webhook');
    setFormDestination(config.destination);
    setFormEvents(config.events);
    setFormEnabled(config.enabled);
    setFormSecret('');
    setFormClearSecret(false);
    setFormScopeId(config.scope_smart_group_id ?? '');
    setModalOpen(true);
  };

  const generateSecret = () => {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    setFormSecret(hex);
    setFormClearSecret(false);
  };

  const handleRetry = async (config: AlertConfig, historyId: number) => {
    try {
      const res = await apiFetch(`/api/backend/alerts/${config.id}/history/${historyId}/retry`, {
        method: 'POST',
      });
      if (res.ok) {
        toast.success('Delivery retried');
        fetchHistory();
      } else {
        const err = await res.json();
        toast.error(formatApiError(err, 'Retry failed'));
      }
    } catch {
      toast.error('Network error');
    }
  };

  const handleSave = async () => {
    const body: Record<string, unknown> = {
      name: formName,
      alert_type: formType,
      destination: formDestination,
      events: formEvents,
      enabled: formEnabled,
    };
    if (formSecret) body.secret = formSecret;
    if (editingConfig && formClearSecret) body.clear_secret = true;
    if (formScopeId === '') {
      if (editingConfig) body.clear_scope = true;
    } else {
      body.scope_smart_group_id = formScopeId;
    }

    try {
      let res;
      if (editingConfig) {
        res = await apiFetch(`/api/backend/alerts/${editingConfig.id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
      } else {
        res = await apiFetch('/api/backend/alerts', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
      }

      if (res.ok) {
        toast.success(editingConfig ? 'Alert config updated' : 'Alert config created');
        setModalOpen(false);
        fetchConfigs();
      } else {
        const err = await res.json();
        toast.error(formatApiError(err, 'Failed to save'));
      }
    } catch {
      toast.error('Network error');
    }
  };

  const handleDelete = async (config: AlertConfig) => {
    if (!confirm(`Delete alert config "${config.name}"?`)) return;
    try {
      const res = await apiFetch(`/api/backend/alerts/${config.id}`, { method: 'DELETE' });
      if (res.ok) {
        toast.success('Alert config deleted');
        fetchConfigs();
      } else {
        toast.error('Failed to delete');
      }
    } catch {
      toast.error('Network error');
    }
  };

  const handleTest = async (config: AlertConfig) => {
    try {
      const res = await apiFetch(`/api/backend/alerts/${config.id}/test`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'sent') {
        toast.success('Test alert sent successfully');
      } else {
        toast.error(data.message || 'Test alert failed');
      }
    } catch {
      toast.error('Network error');
    }
  };

  const handleToggleEnabled = async (config: AlertConfig) => {
    try {
      const res = await apiFetch(`/api/backend/alerts/${config.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !config.enabled }),
      });
      if (res.ok) fetchConfigs();
    } catch {
      toast.error('Failed to toggle');
    }
  };

  const toggleEvent = (evt: string) => {
    setFormEvents(prev =>
      prev.includes(evt) ? prev.filter(e => e !== evt) : [...prev, evt]
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Bell className="text-red-500" size={20} />
          <h2 className="text-lg font-semibold text-content">Alert Configuration</h2>
        </div>
        <Button variant="primary" onClick={openCreateModal} icon={<Plus size={16} />}>
          New Alert Config
        </Button>
      </div>

      {/* Configs Table */}
      <div className="border border-border/60 rounded-lg overflow-hidden">
        <table className="w-full text-sm text-content">
          <thead className="bg-red-900/30 text-content text-xs uppercase">
            <tr>
              <th scope="col" className="px-4 py-3 text-left">Name</th>
              <th scope="col" className="px-4 py-3 text-left">Type</th>
              <th scope="col" className="px-4 py-3 text-left">Events</th>
              <th scope="col" className="px-4 py-3 text-center">Enabled</th>
              <th scope="col" className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/50">
            {loading ? (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-content-subtle">Loading...</td></tr>
            ) : configs.length === 0 ? (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-content-subtle">No alert configs yet. Create one to get started.</td></tr>
            ) : configs.map(config => (
              <tr key={config.id} className="hover:bg-white/[0.03]">
                <td className="px-4 py-3 font-medium">{config.name}</td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                    config.alert_type === 'slack' ? 'bg-purple-900 text-purple-200' : 'bg-slate-900 text-blue-200'
                  }`}>
                    {config.alert_type}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {config.events.slice(0, 3).map(evt => (
                      <span key={evt} className="px-1.5 py-0.5 bg-surface-overlay text-content rounded text-xs">{evt}</span>
                    ))}
                    {config.events.length > 3 && (
                      <span className="px-1.5 py-0.5 bg-surface-overlay text-content-muted rounded text-xs">+{config.events.length - 3} more</span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3 text-center">
                  <button onClick={() => handleToggleEnabled(config)} className="focus:outline-none">
                    <div className={`w-10 h-5 rounded-full relative transition-colors ${config.enabled ? 'bg-green-600' : 'bg-gray-700'}`}>
                      <div className={`w-4 h-4 bg-white rounded-full absolute top-0.5 transition-transform ${config.enabled ? 'translate-x-5' : 'translate-x-0.5'}`} />
                    </div>
                  </button>
                </td>
                <td className="px-4 py-3 text-right">
                  <div className="flex items-center justify-end gap-2">
                    <button onClick={() => handleTest(config)} className="p-1 text-content-muted hover:text-yellow-400" aria-label="Test" title="Test">
                      <TestTube size={16} />
                    </button>
                    <button onClick={() => openEditModal(config)} className="p-1 text-content-muted hover:text-content" aria-label="Edit" title="Edit">
                      <Pencil size={16} />
                    </button>
                    <button onClick={() => handleDelete(config)} className="p-1 text-content-muted hover:text-red-400" aria-label="Delete" title="Delete">
                      <Trash2 size={16} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Alert History Section */}
      <div className="border border-border/60 rounded-lg overflow-hidden">
        <button
          onClick={() => setShowHistory(!showHistory)}
          className="w-full flex items-center justify-between px-4 py-3 bg-red-900/20 text-content hover:bg-red-900/30 transition-colors"
        >
          <span className="font-semibold">Alert History</span>
          {showHistory ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
        </button>
        {showHistory && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-content">
              <thead className="bg-red-900/20 text-content-muted text-xs uppercase">
                <tr>
                  <th scope="col" className="px-4 py-2 text-left">Sent At</th>
                  <th scope="col" className="px-4 py-2 text-left">Event Type</th>
                  <th scope="col" className="px-4 py-2 text-left">Message</th>
                  <th scope="col" className="px-4 py-2 text-center">Status</th>
                  <th scope="col" className="px-4 py-2 text-left">Error</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/30">
                {history.length === 0 ? (
                  <tr><td colSpan={5} className="px-4 py-6 text-center text-content-subtle">No alert history yet.</td></tr>
                ) : history.map(h => (
                  <tr key={h.id} className="hover:bg-white/[0.03]">
                    <td className="px-4 py-2 whitespace-nowrap text-content-muted text-xs">
                      {formatTimestamp(h.sent_at)}
                    </td>
                    <td className="px-4 py-2">
                      <span className="px-1.5 py-0.5 bg-surface-overlay text-content rounded text-xs">{h.event_type}</span>
                    </td>
                    <td className="px-4 py-2 max-w-xs truncate">{h.message}</td>
                    <td className="px-4 py-2 text-center">
                      {h.status === 'sent' ? (
                        <span title="Delivered"><CheckCircle size={16} className="inline text-green-500" /></span>
                      ) : h.status === 'pending' ? (
                        <span title="Pending"><Clock size={16} className="inline text-amber-400" /></span>
                      ) : h.status === 'dead_letter' ? (
                        <span title={`Dead-lettered after ${h.attempt_count} attempts`}><AlertTriangle size={16} className="inline text-red-500" /></span>
                      ) : (
                        <span title={`Failed (attempt ${h.attempt_count})`}><XCircle size={16} className="inline text-red-500" /></span>
                      )}
                      {h.attempt_count > 1 && (
                        <span className="ml-1 text-xs text-content-subtle">x{h.attempt_count}</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-red-400 text-xs max-w-xs truncate">
                      {h.error_message || '-'}
                      {(h.status === 'failed' || h.status === 'dead_letter') && (
                        <button
                          onClick={() => {
                            const cfg = configs.find(c => c.id === h.alert_config_id);
                            if (cfg) handleRetry(cfg, h.id);
                          }}
                          className="ml-2 p-1 text-content-muted hover:text-amber-400"
                          title="Retry delivery"
                        >
                          <RefreshCw size={12} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-surface/70">
          <div className="bg-surface-overlay border border-border/60 rounded-lg w-full max-w-lg p-6 space-y-4 max-h-[90vh] overflow-y-auto">
            <h2 className="text-lg font-bold text-content">
              {editingConfig ? 'Edit Alert Config' : 'Create Alert Config'}
            </h2>

            <div>
              <label className="block text-sm text-content-muted mb-1">Name</label>
              <input
                value={formName}
                onChange={e => setFormName(e.target.value)}
                className="w-full px-3 py-2 bg-surface-sunken border border-border/60 rounded text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                placeholder="e.g. Production Slack Alerts"
              />
            </div>

            <div>
              <label className="block text-sm text-content-muted mb-1">Type</label>
              <select
                value={formType}
                onChange={e => setFormType(e.target.value as 'slack' | 'webhook')}
                className="w-full px-3 py-2 bg-surface-sunken border border-border/60 rounded text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
              >
                <option value="slack">Slack Webhook</option>
                <option value="webhook">Generic Webhook</option>
              </select>
            </div>

            <div>
              <label className="block text-sm text-content-muted mb-1">Destination URL</label>
              <input
                value={formDestination}
                onChange={e => setFormDestination(e.target.value)}
                className="w-full px-3 py-2 bg-surface-sunken border border-border/60 rounded text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                placeholder={formType === 'slack' ? 'https://hooks.slack.com/services/...' : 'https://your-webhook-url.com/...'}
              />
            </div>

            <div>
              <label className="block text-sm text-content-muted mb-2">Events</label>
              <div className="grid grid-cols-2 gap-2 max-h-48 overflow-y-auto">
                {ALL_EVENT_TYPES.map(evt => (
                  <label key={evt} className="flex items-center gap-2 text-sm text-content cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formEvents.includes(evt)}
                      onChange={() => toggleEvent(evt)}
                      className="accent-red-600"
                    />
                    {humanizeLabel(evt)}
                  </label>
                ))}
              </div>
            </div>

            <div>
              <label className="flex items-center gap-2 text-sm text-content-muted mb-1">
                <Key size={14} /> HMAC Secret
                <span className="text-content-subtle font-normal">
                  (optional - signs requests with X-Praxis-Signature: sha256=...)
                </span>
              </label>
              <div className="flex gap-2">
                <input
                  type="password"
                  value={formSecret}
                  onChange={e => { setFormSecret(e.target.value); setFormClearSecret(false); }}
                  className="flex-1 px-3 py-2 bg-surface-sunken border border-border/60 rounded text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong font-mono text-xs"
                  placeholder={editingConfig?.has_secret ? '••• existing secret ••• (leave blank to keep)' : 'Paste or generate a shared secret'}
                />
                <Button variant="outline" onClick={generateSecret} type="button">Generate</Button>
              </div>
              {editingConfig?.has_secret && (
                <label className="flex items-center gap-2 text-xs text-content-subtle mt-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formClearSecret}
                    onChange={e => { setFormClearSecret(e.target.checked); if (e.target.checked) setFormSecret(''); }}
                    className="accent-red-600"
                  />
                  Clear secret (disables signing)
                </label>
              )}
            </div>

            <div>
              <label className="block text-sm text-content-muted mb-1">Scope (smart group)
                <span className="text-content-subtle font-normal"> - only dispatch for events from members</span>
              </label>
              <select
                value={formScopeId}
                onChange={e => setFormScopeId(e.target.value ? Number(e.target.value) : '')}
                className="w-full px-3 py-2 bg-surface-sunken border border-border/60 rounded text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
              >
                <option value="">Fleet-wide (no scope)</option>
                {smartGroups.map(g => (
                  <option key={g.id} value={g.id}>{g.name} ({g.member_count} members)</option>
                ))}
              </select>
            </div>

            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={formEnabled}
                onChange={e => setFormEnabled(e.target.checked)}
                className="accent-red-600"
                id="form-enabled"
              />
              <label htmlFor="form-enabled" className="text-sm text-content">Enabled</label>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <Button variant="outline" onClick={() => setModalOpen(false)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                onClick={handleSave}
                disabled={!formName || !formDestination}
              >
                {editingConfig ? 'Update' : 'Create'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AlertConfigTab;
