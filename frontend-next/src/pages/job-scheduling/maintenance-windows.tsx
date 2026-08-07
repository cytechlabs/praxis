import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { Plus, Pencil, Trash2, RefreshCw, Clock, Calendar, Shield } from 'lucide-react';
import { apiFetch, formatApiError } from '@/utils/api';
import { fetchAllSystems, fetchGroups } from '@/services/systemService';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { PageHeader, Button, StatCard, Card, CardHeader, Badge, EmptyState, ConfirmModal } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';

interface ScheduleDef {
  day_of_week: number[];
  start_time: string;
  end_time: string;
  timezone: string;
}

interface MaintenanceWindowItem {
  id: number;
  name: string;
  target_type: string;
  target_id: number | null;
  target_name: string;
  schedule: ScheduleDef;
  enabled: boolean;
  created_by: number;
  created_at: string;
  updated_at: string;
}

interface UpcomingWindow {
  window_id: number;
  window_name: string;
  target_type: string;
  target_name: string;
  start: string;
  end: string;
}

const DAY_NAMES = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
const DAY_SHORT = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

const scheduleToLabel = (schedule: ScheduleDef): string => {
  const days = schedule.day_of_week.map(d => DAY_SHORT[d] || `Day ${d}`).join(', ');
  return `${days} ${schedule.start_time} - ${schedule.end_time} ${schedule.timezone || 'UTC'}`;
};

const defaultSchedule: ScheduleDef = {
  day_of_week: [0, 1, 2, 3, 4, 5, 6],
  start_time: '02:00',
  end_time: '04:00',
  timezone: 'UTC',
};

const MaintenanceWindows = () => {
  const formatTimestamp = useFormatTimestamp();
  const [windows, setWindows] = useState<MaintenanceWindowItem[]>([]);
  const [upcoming, setUpcoming] = useState<UpcomingWindow[]>([]);
  const [loading, setLoading] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [editingWindow, setEditingWindow] = useState<MaintenanceWindowItem | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [systems, setSystems] = useState<{ id: number; hostname: string }[]>([]);
  const [groups, setGroups] = useState<{ id: number; name: string }[]>([]);
  const [confirmDelete, setConfirmDelete] = useState<MaintenanceWindowItem | null>(null);

  // Form state
  const [formName, setFormName] = useState('');
  const [formTargetType, setFormTargetType] = useState('all');
  const [formTargetId, setFormTargetId] = useState<number | null>(null);
  const [formSchedule, setFormSchedule] = useState<ScheduleDef>({ ...defaultSchedule });
  const [formEnabled, setFormEnabled] = useState(true);

  const loadWindows = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/api/backend/maintenance-windows');
      if (res.ok) {
        const data = await res.json();
        setWindows(data.windows || []);
      }
    } catch {
      toast.error('Failed to load maintenance windows');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadUpcoming = useCallback(async () => {
    try {
      const res = await apiFetch('/api/backend/maintenance-windows/schedule?days=7');
      if (res.ok) {
        const data = await res.json();
        setUpcoming(data.upcoming || []);
      }
    } catch { /* non-critical */ }
  }, []);

  const loadTargets = useCallback(async () => {
    try {
      const [systemsData, groupsData] = await Promise.all([fetchAllSystems(), fetchGroups()]);
      setSystems(systemsData.map((s: { id: number; hostname: string }) => ({ id: s.id, hostname: s.hostname })));
      setGroups(groupsData.map((g: { id: number; name: string }) => ({ id: g.id, name: g.name })));
    } catch { /* best-effort */ }
  }, []);

  useEffect(() => {
    loadWindows();
    loadUpcoming();
    loadTargets();
  }, [loadWindows, loadUpcoming, loadTargets]);

  const resetForm = () => {
    setFormName('');
    setFormTargetType('all');
    setFormTargetId(null);
    setFormSchedule({ ...defaultSchedule });
    setFormEnabled(true);
    setEditingWindow(null);
    setShowForm(false);
  };

  const openCreate = () => {
    resetForm();
    setShowForm(true);
  };

  const openEdit = (w: MaintenanceWindowItem) => {
    setEditingWindow(w);
    setFormName(w.name);
    setFormTargetType(w.target_type);
    setFormTargetId(w.target_id);
    setFormSchedule(w.schedule || { ...defaultSchedule });
    setFormEnabled(w.enabled);
    setShowForm(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formName.trim()) { toast.error('Name is required'); return; }
    if (formTargetType !== 'all' && !formTargetId) { toast.error('Target is required'); return; }

    setSubmitting(true);
    try {
      const payload = {
        name: formName.trim(),
        target_type: formTargetType,
        target_id: formTargetType === 'all' ? null : formTargetId,
        schedule: formSchedule,
        enabled: formEnabled,
      };

      const url = editingWindow
        ? `/api/backend/maintenance-windows/${editingWindow.id}`
        : '/api/backend/maintenance-windows';
      const method = editingWindow ? 'PUT' : 'POST';

      const res = await apiFetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        toast.success(editingWindow ? 'Window updated' : 'Window created');
        resetForm();
        loadWindows();
        loadUpcoming();
      } else {
        const err = await res.json();
        toast.error(formatApiError(err, 'Failed to save window'));
      }
    } catch {
      toast.error('Failed to save maintenance window');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (w: MaintenanceWindowItem) => {
    try {
      const res = await apiFetch(`/api/backend/maintenance-windows/${w.id}`, { method: 'DELETE' });
      if (res.ok) {
        toast.success('Window deleted');
        loadWindows();
        loadUpcoming();
      } else {
        const err = await res.json();
        toast.error(formatApiError(err, 'Failed to delete window'));
      }
    } catch {
      toast.error('Failed to delete window');
    }
  };

  const handleToggleEnabled = async (w: MaintenanceWindowItem) => {
    try {
      const res = await apiFetch(`/api/backend/maintenance-windows/${w.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !w.enabled }),
      });
      if (res.ok) {
        toast.success(w.enabled ? 'Window disabled' : 'Window enabled');
        loadWindows();
      } else {
        const err = await res.json();
        toast.error(formatApiError(err, 'Failed to toggle window'));
      }
    } catch {
      toast.error('Failed to toggle window');
    }
  };

  const toggleDay = (day: number) => {
    const days = formSchedule.day_of_week;
    if (days.includes(day)) {
      setFormSchedule({ ...formSchedule, day_of_week: days.filter(d => d !== day) });
    } else {
      setFormSchedule({ ...formSchedule, day_of_week: [...days, day].sort() });
    }
  };

  return (
    <MainLayout>
        <Head>
          <title>Maintenance Windows | Praxis</title>
        </Head>
        <PageHeader
          title="Maintenance Windows"
          actions={
            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                size="sm"
                icon={<RefreshCw className="w-4 h-4" />}
                onClick={() => { loadWindows(); loadUpcoming(); }}
              >
                Refresh
              </Button>
              <Button
                variant="primary"
                icon={<Plus className="w-4 h-4" />}
                onClick={openCreate}
              >
                Create Window
              </Button>
              <HelpLink slug="jobs-and-scheduling" />
            </div>
          }
        />

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <StatCard label="Total Windows" value={windows.length} icon={<Shield className="w-3 h-3" />} />
          <StatCard label="Active" value={windows.filter(w => w.enabled).length} icon={<Clock className="w-3 h-3" />} />
          <StatCard label="Upcoming (7 days)" value={upcoming.length} icon={<Calendar className="w-3 h-3" />} />
        </div>

        {/* Create/Edit Form */}
        {showForm && (
          <Card className="mb-6">
            <CardHeader>{editingWindow ? 'Edit Window' : 'Create Window'}</CardHeader>
            <div className="px-5 py-4">
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Name *</label>
                    <input
                      type="text"
                      value={formName}
                      onChange={(e) => setFormName(e.target.value)}
                      className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 w-full focus:outline-none focus:border-red-600"
                      placeholder="e.g., Weekend Maintenance"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Target Type</label>
                    <select
                      value={formTargetType}
                      onChange={(e) => { setFormTargetType(e.target.value); setFormTargetId(null); }}
                      className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 w-full focus:outline-none focus:border-red-600"
                    >
                      <option value="all">All Systems</option>
                      <option value="system">Specific System</option>
                      <option value="group">Group</option>
                    </select>
                  </div>
                </div>

                {formTargetType === 'system' && (
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">System</label>
                    <select
                      value={formTargetId || ''}
                      onChange={(e) => setFormTargetId(Number(e.target.value) || null)}
                      className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 w-full focus:outline-none focus:border-red-600"
                    >
                      <option value="">Select system...</option>
                      {systems.map(s => <option key={s.id} value={s.id}>{s.hostname}</option>)}
                    </select>
                  </div>
                )}

                {formTargetType === 'group' && (
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Group</label>
                    <select
                      value={formTargetId || ''}
                      onChange={(e) => setFormTargetId(Number(e.target.value) || null)}
                      className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 w-full focus:outline-none focus:border-red-600"
                    >
                      <option value="">Select group...</option>
                      {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
                    </select>
                  </div>
                )}

                {/* Days of Week */}
                <div>
                  <label className="block text-sm text-gray-400 mb-2">Days of Week</label>
                  <div className="flex gap-2 flex-wrap">
                    {DAY_NAMES.map((name, idx) => (
                      <button
                        key={idx}
                        type="button"
                        onClick={() => toggleDay(idx)}
                        className={`px-3 py-1.5 rounded text-sm border ${
                          formSchedule.day_of_week.includes(idx)
                            ? 'bg-red-600 border-red-500 text-white'
                            : 'bg-gray-950 border-gray-800 text-gray-400 hover:bg-gray-800'
                        }`}
                      >
                        {name}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Time Range */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Start Time</label>
                    <input
                      type="time"
                      value={formSchedule.start_time}
                      onChange={(e) => setFormSchedule({ ...formSchedule, start_time: e.target.value })}
                      className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 w-full focus:outline-none focus:border-red-600"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">End Time</label>
                    <input
                      type="time"
                      value={formSchedule.end_time}
                      onChange={(e) => setFormSchedule({ ...formSchedule, end_time: e.target.value })}
                      className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 w-full focus:outline-none focus:border-red-600"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Timezone</label>
                    <select
                      value={formSchedule.timezone}
                      onChange={(e) => setFormSchedule({ ...formSchedule, timezone: e.target.value })}
                      className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 w-full focus:outline-none focus:border-red-600"
                    >
                      <option value="UTC">UTC</option>
                      <option value="America/New_York">Eastern (US)</option>
                      <option value="America/Chicago">Central (US)</option>
                      <option value="America/Denver">Mountain (US)</option>
                      <option value="America/Los_Angeles">Pacific (US)</option>
                      <option value="Europe/London">London</option>
                      <option value="Europe/Berlin">Berlin</option>
                      <option value="Asia/Tokyo">Tokyo</option>
                    </select>
                  </div>
                </div>

                {/* Enabled */}
                <div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formEnabled}
                      onChange={(e) => setFormEnabled(e.target.checked)}
                      className="w-4 h-4 accent-red-600"
                    />
                    <span className="text-gray-300 text-sm">Enabled</span>
                  </label>
                </div>

                <div className="flex items-center gap-3 pt-2">
                  <Button type="submit" variant="primary" disabled={submitting}>
                    {submitting ? 'Saving...' : editingWindow ? 'Update Window' : 'Create Window'}
                  </Button>
                  <Button variant="outline" onClick={resetForm}>
                    Cancel
                  </Button>
                </div>
              </form>
            </div>
          </Card>
        )}

        {/* Windows List */}
        <Card className="mb-6">
          <CardHeader>Configured Windows</CardHeader>
          <div className="px-5 py-4">
            {loading && <div className="p-4 text-gray-400">Loading...</div>}

            {!loading && windows.length === 0 && (
              <EmptyState
                title="No maintenance windows configured"
                description='Click "Create Window" to get started.'
              />
            )}

            {!loading && windows.length > 0 && (
              <div className="space-y-2">
                <div className="grid grid-cols-6 gap-4 p-3 bg-gray-900 border-b border-gray-800 font-medium text-gray-200 text-sm rounded-t-lg">
                  <div>Name</div>
                  <div>Target</div>
                  <div>Schedule</div>
                  <div>Status</div>
                  <div>Created</div>
                  <div>Actions</div>
                </div>
                {windows.map(w => (
                  <div key={w.id} className="grid grid-cols-6 gap-4 p-3 border-b border-gray-800 text-gray-300 hover:bg-white/[0.03]/50 text-sm items-center">
                    <div className="font-medium truncate">{w.name}</div>
                    <div className="truncate">
                      <Badge variant="neutral" className="mr-1">{w.target_type}</Badge>
                      {w.target_name}
                    </div>
                    <div className="truncate text-xs" title={scheduleToLabel(w.schedule)}>{scheduleToLabel(w.schedule)}</div>
                    <div>
                      <button onClick={() => handleToggleEnabled(w)}>
                        <Badge variant={w.enabled ? 'success' : 'neutral'}>
                          {w.enabled ? 'Active' : 'Disabled'}
                        </Badge>
                      </button>
                    </div>
                    <div className="text-xs text-gray-400">{formatTimestamp(w.created_at, { dateOnly: true })}</div>
                    <div className="flex gap-1">
                      <Button variant="outline" size="sm" onClick={() => openEdit(w)} title="Edit">
                        <Pencil className="w-3 h-3" />
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => setConfirmDelete(w)} title="Delete">
                        <Trash2 className="w-3 h-3" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Card>

        {/* Upcoming Schedule */}
        <Card>
          <CardHeader>Upcoming Windows (Next 7 Days)</CardHeader>
          <div className="px-5 py-4">
            {upcoming.length === 0 ? (
              <EmptyState title="No upcoming maintenance windows" />
            ) : (
              <div className="space-y-2">
                <div className="grid grid-cols-4 gap-4 p-3 bg-gray-900 border-b border-gray-800 font-medium text-gray-200 text-sm rounded-t-lg">
                  <div>Window</div>
                  <div>Target</div>
                  <div>Start</div>
                  <div>End</div>
                </div>
                {upcoming.map((u, idx) => (
                  <div key={idx} className="grid grid-cols-4 gap-4 p-3 border-b border-gray-800 text-gray-300 text-sm">
                    <div className="font-medium">{u.window_name}</div>
                    <div>
                      <Badge variant="neutral" className="mr-1">{u.target_type}</Badge>
                      {u.target_name}
                    </div>
                    <div>{formatTimestamp(u.start)}</div>
                    <div>{formatTimestamp(u.end)}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Card>

        <ConfirmModal
          open={!!confirmDelete}
          onClose={() => setConfirmDelete(null)}
          onConfirm={() => {
            if (confirmDelete) {
              handleDelete(confirmDelete);
              setConfirmDelete(null);
            }
          }}
          title="Delete Maintenance Window"
          message={confirmDelete ? `Delete maintenance window "${confirmDelete.name}"?` : ''}
          confirmLabel="Delete"
          variant="danger"
        />
    </MainLayout>
  );
};

export default MaintenanceWindows;
