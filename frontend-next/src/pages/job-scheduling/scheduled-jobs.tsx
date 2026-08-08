import React, { useState, useEffect, useCallback, useRef } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import Pagination from '@/components/Pagination';
import { Plus, Play, Pause, Pencil, Trash2, RefreshCw, Clock, Filter, Eye } from 'lucide-react';
import { fetchJobs, createJob, updateJob, deleteJob, runJob, dryRunJob, Job, JobCreate, JobUpdate, JobListResponse, DryRunResponse } from '@/services/jobService';
import { fetchAllSystems, fetchGroups } from '@/services/systemService';
import { fetchTags, Tag as TagType } from '@/services/tagService';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { PageHeader, Button, StatCard, Card, CardHeader, Badge, statusToBadgeVariant, EmptyState, ConfirmModal, Select } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';

interface ScheduleConfig {
  frequency: string; // once, daily, weekly, monthly
  time: string; // HH:MM
  dayOfWeek: string; // 0-6 (Sun-Sat)
  dayOfMonth: string; // 1-31
}

const defaultSchedule: ScheduleConfig = {
  frequency: 'daily',
  time: '02:00',
  dayOfWeek: '0',
  dayOfMonth: '1',
};

const scheduleToCron = (s: ScheduleConfig): string => {
  const [hour, minute] = s.time.split(':');
  switch (s.frequency) {
    case 'daily': return `${minute} ${hour} * * *`;
    case 'weekly': return `${minute} ${hour} * * ${s.dayOfWeek}`;
    case 'monthly': return `${minute} ${hour} ${s.dayOfMonth} * *`;
    default: return `${minute} ${hour} * * *`;
  }
};

const cronToSchedule = (cron: string): ScheduleConfig => {
  const parts = cron.split(' ');
  if (parts.length !== 5) return { ...defaultSchedule };
  const [minute, hour, dom, , dow] = parts;
  const time = `${hour.padStart(2, '0')}:${minute.padStart(2, '0')}`;
  if (dom !== '*') return { frequency: 'monthly', time, dayOfWeek: '0', dayOfMonth: dom };
  if (dow !== '*') return { frequency: 'weekly', time, dayOfWeek: dow, dayOfMonth: '1' };
  return { frequency: 'daily', time, dayOfWeek: '0', dayOfMonth: '1' };
};

const scheduleToLabel = (cron: string | null): string => {
  if (!cron) return 'One-time';
  const s = cronToSchedule(cron);
  const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  switch (s.frequency) {
    case 'daily': return `Daily at ${s.time}`;
    case 'weekly': return `${days[parseInt(s.dayOfWeek)] || 'Sunday'}s at ${s.time}`;
    case 'monthly': return `${ordinal(parseInt(s.dayOfMonth))} of each month at ${s.time}`;
    default: return cron;
  }
};

const ordinal = (n: number): string => {
  const s = ['th', 'st', 'nd', 'rd'];
  const v = n % 100;
  return n + (s[(v - 20) % 10] || s[v] || s[0]);
};

const defaultFormData: JobCreate = {
  name: '',
  description: '',
  job_type: 'update',
  schedule: '',
  is_recurring: false,
  target_type: 'all',
  target_ids: [],
  package_filter: undefined,
  tag_match_logic: 'or',
  max_parallel: 1,
  depends_on_job_id: null,
  chain_condition: 'on_success',
};

const ScheduledJobs = () => {
  const formatTimestamp = useFormatTimestamp();
  const [jobs, setJobs] = useState<Job[]>([]);
  const [loading, setLoading] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [editingJob, setEditingJob] = useState<Job | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [systems, setSystems] = useState<{ id: number; hostname: string }[]>([]);
  const [groups, setGroups] = useState<{ id: number; name: string }[]>([]);
  const [tags, setTags] = useState<{ id: number; name: string; color: string }[]>([]);
  const [smartGroups, setSmartGroups] = useState<{ id: number; name: string; member_count: number }[]>([]);
  const [runningJobId, setRunningJobId] = useState<number | null>(null);
  const [dryRunningId, setDryRunningId] = useState<number | null>(null);
  const [dryRunResult, setDryRunResult] = useState<DryRunResponse | null>(null);
  const [formData, setFormData] = useState<JobCreate>({ ...defaultFormData });
  const [packageNames, setPackageNames] = useState('');
  const [packageKeywords, setPackageKeywords] = useState('');
  const [securityOnly, setSecurityOnly] = useState(false);
  const [showPackageFilter, setShowPackageFilter] = useState(false);
  const [showDependency, setShowDependency] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [pageOffset, setPageOffset] = useState(0);
  const pageLimit = 25;
  const [scheduleConfig, setScheduleConfig] = useState<ScheduleConfig>({ ...defaultSchedule });
  const [confirmDelete, setConfirmDelete] = useState<Job | null>(null);

  const loadJobs = useCallback(async () => {
    setLoading(true);
    try {
      const statusParam = statusFilter === 'all' ? undefined : statusFilter;
      const typeParam = typeFilter === 'all' ? undefined : typeFilter;
      const response: JobListResponse = await fetchJobs(statusParam, typeParam);
      setJobs(response.jobs);
      setPageOffset(0);
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Failed to load jobs');
    } finally {
      setLoading(false);
    }
  }, [statusFilter, typeFilter]);

  const loadSystemsAndGroups = useCallback(async () => {
    try {
      const [systemsData, groupsData, tagsData] = await Promise.all([fetchAllSystems(), fetchGroups(), fetchTags()]);
      setSystems(systemsData.map((s) => ({ id: s.id, hostname: s.hostname })));
      setGroups(groupsData.map((g) => ({ id: g.id, name: g.name })));
      setTags(tagsData.map((t: TagType) => ({ id: t.id, name: t.name, color: t.color })));
      // Smart groups (best-effort - may be empty)
      try {
        const { apiFetch } = await import('@/utils/api');
        const res = await apiFetch('/api/backend/smart-groups');
        if (res.ok) {
          const data = await res.json();
          setSmartGroups((data.smart_groups || []).map((g: { id: number; name: string; member_count: number }) => ({ id: g.id, name: g.name, member_count: g.member_count })));
        }
      } catch { /* ignore */ }
    } catch {
      // Systems/groups/tags load is best-effort
    }
  }, []);

  useEffect(() => {
    loadJobs();
  }, [loadJobs]);

  // Auto-refresh every 5s when any job is running
  const hasRunning = jobs.some((j) => j.status === 'running');
  const filtersRef = useRef({ statusFilter, typeFilter });
  filtersRef.current = { statusFilter, typeFilter };

  useEffect(() => {
    if (!hasRunning) return;

    const interval = setInterval(async () => {
      try {
        const sf = filtersRef.current.statusFilter === 'all' ? undefined : filtersRef.current.statusFilter;
        const tf = filtersRef.current.typeFilter === 'all' ? undefined : filtersRef.current.typeFilter;
        const response: JobListResponse = await fetchJobs(sf, tf);
        setJobs(response.jobs);
      } catch {
        // Silent refresh failure
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [hasRunning]);

  useEffect(() => {
    loadSystemsAndGroups();
  }, [loadSystemsAndGroups]);

  const getTargetDisplay = (job: Job) => {
    if (job.target_type === 'all') return 'All Systems';
    if (job.target_type === 'group') {
      const names = (job.target_ids || []).map((id) => groups.find((g) => g.id === id)?.name || `Group ${id}`);
      return names.join(', ') || 'No groups';
    }
    if (job.target_type === 'tag') {
      const names = (job.target_ids || []).map((id) => tags.find((t) => t.id === id)?.name || `Tag ${id}`);
      const logic = job.tag_match_logic === 'and' ? ' (ALL)' : ' (ANY)';
      return (names.join(', ') || 'No tags') + (names.length > 1 ? logic : '');
    }
    if (job.target_type === 'smart_group') {
      const names = (job.target_ids || []).map((id) => smartGroups.find((g) => g.id === id)?.name || `Smart Group ${id}`);
      return names.join(', ') || 'No smart groups';
    }
    const names = (job.target_ids || []).map((id) => systems.find((s) => s.id === id)?.hostname || `System ${id}`);
    return names.join(', ') || 'No systems';
  };

  const resetForm = () => {
    setFormData({ ...defaultFormData });
    setPackageNames('');
    setPackageKeywords('');
    setSecurityOnly(false);
    setShowPackageFilter(false);
    setShowDependency(false);
    setScheduleConfig({ ...defaultSchedule });
    setEditingJob(null);
    setShowForm(false);
  };

  const openCreateForm = () => {
    resetForm();
    setShowForm(true);
  };

  const openEditForm = (job: Job) => {
    setEditingJob(job);
    setFormData({
      name: job.name,
      description: job.description || '',
      job_type: job.job_type,
      schedule: job.schedule || '',
      is_recurring: job.is_recurring,
      target_type: job.target_type,
      target_ids: job.target_ids || [],
      package_filter: job.package_filter || undefined,
      tag_match_logic: job.tag_match_logic || 'or',
      max_parallel: job.max_parallel || 1,
    });
    if (job.package_filter) {
      setPackageNames((job.package_filter.names || []).join(', '));
      setPackageKeywords((job.package_filter.keywords || []).join(', '));
      setSecurityOnly(job.package_filter.security_only || false);
      setShowPackageFilter(true);
    } else {
      setPackageNames('');
      setPackageKeywords('');
      setSecurityOnly(false);
      setShowPackageFilter(false);
    }
    if (job.depends_on_job_id) {
      setShowDependency(true);
      setFormData((prev) => ({ ...prev, depends_on_job_id: job.depends_on_job_id, chain_condition: job.chain_condition || 'on_success' }));
    } else {
      setShowDependency(false);
    }
    if (job.schedule) {
      setScheduleConfig(cronToSchedule(job.schedule));
    } else {
      setScheduleConfig({ ...defaultSchedule });
    }
    setShowForm(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name.trim()) {
      toast.error('Job name is required');
      return;
    }
    if (formData.is_recurring && !scheduleConfig.time) {
      toast.error('Schedule time is required for recurring jobs');
      return;
    }

    setSubmitting(true);
    try {
      const payload: JobCreate = {
        name: formData.name.trim(),
        description: formData.description?.trim() || undefined,
        job_type: formData.job_type,
        schedule: formData.is_recurring ? scheduleToCron(scheduleConfig) : undefined,
        is_recurring: formData.is_recurring,
        target_type: formData.target_type,
        target_ids: formData.target_type === 'all' ? undefined : formData.target_ids,
        tag_match_logic: formData.target_type === 'tag' ? (formData.tag_match_logic || 'or') : undefined,
        max_parallel: formData.max_parallel || 1,
        package_filter: showPackageFilter
          ? {
              names: packageNames.trim() ? packageNames.split(',').map((s) => s.trim()).filter(Boolean) : undefined,
              keywords: packageKeywords.trim() ? packageKeywords.split(',').map((s) => s.trim()).filter(Boolean) : undefined,
              security_only: securityOnly || undefined,
            }
          : undefined,
        depends_on_job_id: showDependency ? (formData.depends_on_job_id || null) : null,
        chain_condition: showDependency ? (formData.chain_condition || 'on_success') : undefined,
      };

      if (editingJob) {
        await updateJob(editingJob.id, payload as JobUpdate);
        toast.success('Job updated successfully');
      } else {
        await createJob(payload);
        toast.success('Job created successfully');
      }
      resetForm();
      loadJobs();
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Failed to save job');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (job: Job) => {
    try {
      await deleteJob(job.id);
      toast.success('Job deleted successfully');
      loadJobs();
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Failed to delete job');
    }
  };

  const handleRunNow = async (job: Job) => {
    setRunningJobId(job.id);
    try {
      const result = await runJob(job.id);
      toast.success(result.message || 'Job triggered successfully');
      loadJobs();
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Failed to run job');
    } finally {
      setRunningJobId(null);
    }
  };

  const handleDryRun = async (job: Job) => {
    setDryRunningId(job.id);
    try {
      const result = await dryRunJob(job.id);
      setDryRunResult(result);
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Dry run failed');
    } finally {
      setDryRunningId(null);
    }
  };

  const handleTogglePause = async (job: Job) => {
    const newStatus = job.status === 'paused' ? 'scheduled' : 'paused';
    try {
      await updateJob(job.id, { status: newStatus });
      toast.success(newStatus === 'paused' ? 'Job paused' : 'Job resumed');
      loadJobs();
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Failed to update job status');
    }
  };

  const handleTargetToggle = (id: number) => {
    const current = formData.target_ids || [];
    if (current.includes(id)) {
      setFormData({ ...formData, target_ids: current.filter((i) => i !== id) });
    } else {
      setFormData({ ...formData, target_ids: [...current, id] });
    }
  };

  // Stats
  const totalJobs = jobs.length;
  const recurringJobs = jobs.filter((j) => j.is_recurring).length;
  const oneTimeJobs = jobs.filter((j) => !j.is_recurring).length;
  const pausedJobs = jobs.filter((j) => j.status === 'paused').length;

  return (
    <MainLayout>
        <Head>
          <title>Scheduled Jobs | Praxis</title>
        </Head>
        <PageHeader
          title="Scheduled Jobs"
          actions={
            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                size="sm"
                icon={<RefreshCw className="w-4 h-4" />}
                onClick={() => loadJobs()}
              >
                Refresh
              </Button>
              <Button
                variant="primary"
                icon={<Plus className="w-4 h-4" />}
                onClick={openCreateForm}
              >
                Create Job
              </Button>
              <HelpLink slug="jobs-and-scheduling" />
            </div>
          }
        />

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <StatCard label="Total Jobs" value={totalJobs} />
          <StatCard label="Recurring" value={recurringJobs} icon={<RefreshCw className="w-3 h-3" />} />
          <StatCard label="One-time" value={oneTimeJobs} icon={<Clock className="w-3 h-3" />} />
          <StatCard label="Paused" value={pausedJobs} icon={<Pause className="w-3 h-3" />} />
        </div>

        {/* Create/Edit Form */}
        {showForm && (
          <Card className="mb-6">
            <CardHeader>{editingJob ? 'Edit Job' : 'Create Job'}</CardHeader>
            <div className="px-5 py-4">
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Name */}
                  <div>
                    <label className="block text-sm text-content-muted mb-1">Name *</label>
                    <input
                      type="text"
                      value={formData.name}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      className="bg-surface-sunken border border-border rounded-lg px-3 py-2 text-content w-full focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                      placeholder="e.g., Weekly Security Updates"
                    />
                  </div>

                  {/* Job Type */}
                  <div>
                    <label className="block text-sm text-content-muted mb-1">Job Type</label>
                    <select
                      value={formData.job_type}
                      onChange={(e) => setFormData({ ...formData, job_type: e.target.value })}
                      className="bg-surface-sunken border border-border rounded-lg px-3 py-2 text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong w-full"
                    >
                      <option value="update">Update</option>
                      <option value="security_update">Security Update</option>
                      <option value="audit">Audit</option>
                      <option value="package_scan">Package Scan</option>
                    </select>
                    <p className="text-xs text-content-subtle mt-1">
                      {formData.job_type === 'update' || formData.job_type === 'security_update'
                        ? 'Scheduled runs execute only inside a maintenance window.'
                        : 'Read/refresh job - scheduled runs execute any time; no maintenance window required.'}
                    </p>
                  </div>
                </div>

                {/* Description */}
                <div>
                  <label className="block text-sm text-content-muted mb-1">Description</label>
                  <textarea
                    value={formData.description || ''}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    className="bg-surface-sunken border border-border rounded-lg px-3 py-2 text-content w-full focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                    rows={2}
                    placeholder="Optional description of this job"
                  />
                </div>

                {/* Recurring + Schedule */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm text-content-muted mb-1">Recurring</label>
                    <label className="flex items-center gap-2 cursor-pointer mt-1">
                      <input
                        type="checkbox"
                        checked={formData.is_recurring}
                        onChange={(e) => setFormData({ ...formData, is_recurring: e.target.checked })}
                        className="w-4 h-4 accent-red-600"
                      />
                      <span className="text-content text-sm">This is a recurring job</span>
                    </label>
                  </div>

                  {formData.is_recurring && (
                    <div>
                      <label className="block text-sm text-content-muted mb-1">Schedule *</label>
                      <div className="flex items-center gap-2 flex-wrap">
                        <select
                          value={scheduleConfig.frequency}
                          onChange={(e) => setScheduleConfig({ ...scheduleConfig, frequency: e.target.value })}
                          className="bg-surface-sunken border border-border rounded-lg px-3 py-2 text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                        >
                          <option value="daily">Every day</option>
                          <option value="weekly">Every week on</option>
                          <option value="monthly">Every month on the</option>
                        </select>
                        {scheduleConfig.frequency === 'weekly' && (
                          <select
                            value={scheduleConfig.dayOfWeek}
                            onChange={(e) => setScheduleConfig({ ...scheduleConfig, dayOfWeek: e.target.value })}
                            className="bg-surface-sunken border border-border rounded-lg px-3 py-2 text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                          >
                            <option value="0">Sunday</option>
                            <option value="1">Monday</option>
                            <option value="2">Tuesday</option>
                            <option value="3">Wednesday</option>
                            <option value="4">Thursday</option>
                            <option value="5">Friday</option>
                            <option value="6">Saturday</option>
                          </select>
                        )}
                        {scheduleConfig.frequency === 'monthly' && (
                          <select
                            value={scheduleConfig.dayOfMonth}
                            onChange={(e) => setScheduleConfig({ ...scheduleConfig, dayOfMonth: e.target.value })}
                            className="bg-surface-sunken border border-border rounded-lg px-3 py-2 text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                          >
                            {Array.from({ length: 28 }, (_, i) => (
                              <option key={i + 1} value={String(i + 1)}>{ordinal(i + 1)}</option>
                            ))}
                          </select>
                        )}
                        <span className="text-content-muted text-sm">at</span>
                        <input
                          type="time"
                          value={scheduleConfig.time}
                          onChange={(e) => setScheduleConfig({ ...scheduleConfig, time: e.target.value })}
                          className="bg-surface-sunken border border-border rounded-lg px-3 py-2 text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                        />
                      </div>
                    </div>
                  )}
                </div>

                {/* Target */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm text-content-muted mb-1">Target Type</label>
                    <select
                      value={formData.target_type}
                      onChange={(e) => setFormData({ ...formData, target_type: e.target.value, target_ids: [] })}
                      className="bg-surface-sunken border border-border rounded-lg px-3 py-2 text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong w-full"
                    >
                      <option value="all">All Systems</option>
                      <option value="system">Specific Systems</option>
                      <option value="group">Groups</option>
                      <option value="smart_group">Smart Groups</option>
                      <option value="tag">Tags</option>
                    </select>
                  </div>

                  {formData.target_type === 'system' && (
                    <div>
                      <label className="block text-sm text-content-muted mb-1">Select Systems</label>
                      <div className="bg-surface-sunken border border-border rounded-lg p-3 max-h-40 overflow-y-auto space-y-1">
                        {systems.length === 0 && <p className="text-content-subtle text-sm">No systems available</p>}
                        {systems.map((s) => (
                          <label key={s.id} className="flex items-center gap-2 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={(formData.target_ids || []).includes(s.id)}
                              onChange={() => handleTargetToggle(s.id)}
                              className="w-4 h-4 accent-red-600"
                            />
                            <span className="text-content text-sm">{s.hostname}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  )}

                  {formData.target_type === 'group' && (
                    <div>
                      <label className="block text-sm text-content-muted mb-1">Select Groups</label>
                      <div className="bg-surface-sunken border border-border rounded-lg p-3 max-h-40 overflow-y-auto space-y-1">
                        {groups.length === 0 && <p className="text-content-subtle text-sm">No groups available</p>}
                        {groups.map((g) => (
                          <label key={g.id} className="flex items-center gap-2 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={(formData.target_ids || []).includes(g.id)}
                              onChange={() => handleTargetToggle(g.id)}
                              className="w-4 h-4 accent-red-600"
                            />
                            <span className="text-content text-sm">{g.name}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  )}

                  {formData.target_type === 'smart_group' && (
                    <div>
                      <label className="block text-sm text-content-muted mb-1">Select Smart Groups</label>
                      <div className="bg-surface-sunken border border-border rounded-lg p-3 max-h-40 overflow-y-auto space-y-1">
                        {smartGroups.length === 0 && <p className="text-content-subtle text-sm">No smart groups defined</p>}
                        {smartGroups.map((g) => (
                          <label key={g.id} className="flex items-center gap-2 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={(formData.target_ids || []).includes(g.id)}
                              onChange={() => handleTargetToggle(g.id)}
                              className="w-4 h-4 accent-red-600"
                            />
                            <span className="text-content text-sm">{g.name} <span className="text-content-subtle text-xs">({g.member_count} members)</span></span>
                          </label>
                        ))}
                      </div>
                    </div>
                  )}

                  {formData.target_type === 'tag' && (
                    <div>
                      <label className="block text-sm text-content-muted mb-1">Select Tags</label>
                      <div className="bg-surface-sunken border border-border rounded-lg p-3 max-h-40 overflow-y-auto space-y-1">
                        {tags.length === 0 && <p className="text-content-subtle text-sm">No tags available</p>}
                        {tags.map((t) => (
                          <label key={t.id} className="flex items-center gap-2 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={(formData.target_ids || []).includes(t.id)}
                              onChange={() => handleTargetToggle(t.id)}
                              className="w-4 h-4 accent-red-600"
                            />
                            <span className="w-3 h-3 rounded-full inline-block flex-shrink-0" style={{ backgroundColor: t.color }} />
                            <span className="text-content text-sm">{t.name}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Tag Match Logic */}
                {formData.target_type === 'tag' && (formData.target_ids?.length || 0) > 1 && (
                  <div>
                    <label className="block text-sm text-content-muted mb-1">Match Logic</label>
                    <div className="flex gap-3">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="radio"
                          name="tagLogicScheduled"
                          value="or"
                          checked={formData.tag_match_logic !== 'and'}
                          onChange={() => setFormData({ ...formData, tag_match_logic: 'or' })}
                          className="accent-red-600"
                        />
                        <span className="text-content text-sm">Any tag (OR)</span>
                      </label>
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="radio"
                          name="tagLogicScheduled"
                          value="and"
                          checked={formData.tag_match_logic === 'and'}
                          onChange={() => setFormData({ ...formData, tag_match_logic: 'and' })}
                          className="accent-red-600"
                        />
                        <span className="text-content text-sm">All tags (AND)</span>
                      </label>
                    </div>
                  </div>
                )}

                {/* Package Filter */}
                <div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={showPackageFilter}
                      onChange={(e) => setShowPackageFilter(e.target.checked)}
                      className="w-4 h-4 accent-red-600"
                    />
                    <span className="text-content text-sm">Add package filter (optional)</span>
                  </label>

                  {showPackageFilter && (
                    <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-4 pl-6">
                      <div>
                        <label className="block text-sm text-content-muted mb-1">Package Names (comma-separated)</label>
                        <input
                          type="text"
                          value={packageNames}
                          onChange={(e) => setPackageNames(e.target.value)}
                          className="bg-surface-sunken border border-border rounded-lg px-3 py-2 text-content w-full focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                          placeholder="e.g., openssl, nginx, curl"
                        />
                      </div>
                      <div>
                        <label className="block text-sm text-content-muted mb-1">Keywords (comma-separated)</label>
                        <input
                          type="text"
                          value={packageKeywords}
                          onChange={(e) => setPackageKeywords(e.target.value)}
                          className="bg-surface-sunken border border-border rounded-lg px-3 py-2 text-content w-full focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                          placeholder="e.g., security, critical"
                        />
                      </div>
                      <div>
                        <label className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={securityOnly}
                            onChange={(e) => setSecurityOnly(e.target.checked)}
                            className="w-4 h-4 accent-red-600"
                          />
                          <span className="text-content text-sm">Security updates only</span>
                        </label>
                      </div>
                    </div>
                  )}
                </div>

                {/* Concurrency Control (PRA-101) */}
                <div>
                  <label className="block text-sm text-content-muted mb-1">
                    Max Parallel Systems
                  </label>
                  <div className="flex items-center gap-3">
                    <input
                      type="number"
                      min={1}
                      max={50}
                      value={formData.max_parallel || 1}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          max_parallel: Math.max(1, Math.min(50, parseInt(e.target.value) || 1)),
                        })
                      }
                      className="bg-surface-sunken border border-border rounded-lg px-3 py-2 text-content w-28 focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                    />
                    <span className="text-content-subtle text-sm">
                      {(formData.max_parallel || 1) === 1
                        ? 'Sequential (one system at a time, safest)'
                        : `Run on up to ${formData.max_parallel} systems in parallel`}
                    </span>
                  </div>
                </div>

                {/* Job Dependency / Chaining (PRA-81) */}
                <div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={showDependency}
                      onChange={(e) => {
                        setShowDependency(e.target.checked);
                        if (!e.target.checked) {
                          setFormData({ ...formData, depends_on_job_id: null, chain_condition: 'on_success' });
                        }
                      }}
                      className="w-4 h-4 accent-red-600"
                    />
                    <span className="text-content text-sm">Run after another job (chain dependency)</span>
                  </label>

                  {showDependency && (
                    <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-4 pl-6">
                      <div>
                        <label className="block text-sm text-content-muted mb-1">Run After Job</label>
                        <select
                          value={formData.depends_on_job_id || ''}
                          onChange={(e) => setFormData({ ...formData, depends_on_job_id: e.target.value ? Number(e.target.value) : null })}
                          className="bg-surface-sunken border border-border rounded-lg px-3 py-2 text-content w-full focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                        >
                          <option value="">None (no dependency)</option>
                          {jobs.filter((j) => j.id !== editingJob?.id).map((j) => (
                            <option key={j.id} value={j.id}>{j.name}</option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="block text-sm text-content-muted mb-1">Condition</label>
                        <select
                          value={formData.chain_condition || 'on_success'}
                          onChange={(e) => setFormData({ ...formData, chain_condition: e.target.value })}
                          className="bg-surface-sunken border border-border rounded-lg px-3 py-2 text-content w-full focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                        >
                          <option value="on_success">On Success (only if dependency succeeded)</option>
                          <option value="on_complete">On Completion (regardless of outcome)</option>
                          <option value="on_failure">On Failure (only if dependency failed)</option>
                        </select>
                      </div>
                    </div>
                  )}
                </div>

                {/* Form Actions */}
                <div className="flex items-center gap-3 pt-2">
                  <Button type="submit" variant="primary" disabled={submitting}>
                    {submitting ? 'Saving...' : editingJob ? 'Update Job' : 'Create Job'}
                  </Button>
                  <Button variant="outline" onClick={resetForm}>
                    Cancel
                  </Button>
                </div>
              </form>
            </div>
          </Card>
        )}

        {/* Filters */}
        <Card>
          <div className="p-6">
            <div className="flex items-center gap-4 mb-4">
              <Filter className="w-4 h-4 text-content-muted" />
              <div className="flex items-center gap-2">
                <label className="text-sm text-content-muted">Status:</label>
                <Select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                >
                  <option value="all">All</option>
                  <option value="scheduled">Scheduled</option>
                  <option value="running">Running</option>
                  <option value="completed">Completed</option>
                  <option value="failed">Failed</option>
                  <option value="paused">Paused</option>
                  <option value="cancelled">Cancelled</option>
                </Select>
              </div>
              <div className="flex items-center gap-2">
                <label className="text-sm text-content-muted">Job Type:</label>
                <Select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                >
                  <option value="all">All</option>
                  <option value="update">Update</option>
                  <option value="security_update">Security Update</option>
                  <option value="audit">Audit</option>
                  <option value="package_scan">Package Scan</option>
                </Select>
              </div>
            </div>

            {/* Table Header */}
            <div className="grid grid-cols-8 gap-4 p-4 bg-surface-raised border-b border-border font-medium text-content text-sm rounded-t-lg">
              <div>Name</div>
              <div>Job Type</div>
              <div>Schedule</div>
              <div>Target</div>
              <div>Next Run</div>
              <div>Last Run</div>
              <div>Status</div>
              <div>Actions</div>
            </div>

            {/* Loading */}
            {loading && <div className="p-4 text-content-muted">Loading...</div>}

            {/* Paginated view */}
            {!loading && jobs.length === 0 && (
              <EmptyState
                title="No scheduled jobs found"
                description='Click "Create Job" to get started.'
              />
            )}

            {/* Table Rows */}
            {!loading &&
              jobs.slice(pageOffset, pageOffset + pageLimit).map((job) => (
                <div key={job.id} className="grid grid-cols-8 gap-4 p-4 border-b border-border text-content hover:bg-white/[0.03]/50 text-sm items-center">
                  <div className="truncate font-medium" title={job.name}>
                    {job.name}
                    {job.depends_on_job_id && (
                      <span className="ml-1 text-xs text-content" title={`Depends on: ${job.dependency_name || 'Job #' + job.depends_on_job_id} (${job.chain_condition || 'on_success'})`}>
                        &rarr; {job.dependency_name || `Job #${job.depends_on_job_id}`}
                      </span>
                    )}
                  </div>
                  <div className="capitalize">{job.job_type.replace('_', ' ')}</div>
                  <div className="truncate" title={job.schedule || undefined}>
                    {job.is_recurring ? (
                      <span className="flex items-center gap-1"><RefreshCw className="w-3 h-3 text-content" /> {scheduleToLabel(job.schedule)}</span>
                    ) : (
                      <span className="flex items-center gap-1"><Clock className="w-3 h-3 text-content-muted" /> One-time</span>
                    )}
                  </div>
                  <div className="truncate" title={getTargetDisplay(job)}>{getTargetDisplay(job)}</div>
                  <div>{job.next_run ? formatTimestamp(job.next_run) : '-'}</div>
                  <div>{job.last_run ? formatTimestamp(job.last_run) : '-'}</div>
                  <div>
                    <Badge variant={statusToBadgeVariant(job.status)}>{job.status}</Badge>
                  </div>
                  <div className="flex items-center gap-1 flex-wrap">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleRunNow(job)}
                      disabled={runningJobId === job.id}
                      loading={runningJobId === job.id}
                      icon={runningJobId !== job.id ? <Play className="w-3 h-3" /> : undefined}
                      title="Run Now"
                    />
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleDryRun(job)}
                      disabled={dryRunningId === job.id}
                      loading={dryRunningId === job.id}
                      icon={dryRunningId !== job.id ? <Eye className="w-3 h-3" /> : undefined}
                      title="Dry Run (preview)"
                    />
                    {job.is_recurring && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleTogglePause(job)}
                        title={job.status === 'paused' ? 'Resume' : 'Pause'}
                        icon={job.status === 'paused' ? <Play className="w-3 h-3 text-green-400" /> : <Pause className="w-3 h-3 text-orange-400" />}
                      />
                    )}
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => openEditForm(job)}
                      title="Edit"
                      icon={<Pencil className="w-3 h-3" />}
                    />
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setConfirmDelete(job)}
                      title="Delete"
                      icon={<Trash2 className="w-3 h-3" />}
                    />
                  </div>
                </div>
              ))}
            {jobs.length > pageLimit && (
              <Pagination
                offset={pageOffset}
                limit={pageLimit}
                total={jobs.length}
                onPageChange={setPageOffset}
              />
            )}
          </div>
        </Card>

        {/* Dry Run Modal (PRA-82) */}
        {dryRunResult && (
          <div className="fixed inset-0 bg-surface/70 flex items-center justify-center p-4 z-50">
            <div className="bg-surface-overlay border border-border-strong rounded-lg p-6 max-w-4xl w-full max-h-[80vh] overflow-y-auto">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold text-content">
                  Dry Run: {dryRunResult.job_name}
                </h2>
                <button
                  onClick={() => setDryRunResult(null)}
                  className="text-content-muted hover:text-content"
                >
                  ✕
                </button>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                <StatCard label="Job Type" value={dryRunResult.job_type.replace('_', ' ')} />
                <StatCard label="Systems Targeted" value={dryRunResult.systems_targeted} />
                <StatCard label="Total Packages Affected" value={dryRunResult.total_packages_affected} />
              </div>
              <div className="space-y-3">
                {dryRunResult.preview.map((sys) => (
                  <div key={sys.system_id} className="bg-surface-raised border border-border-strong rounded p-3">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-content">{sys.hostname}</span>
                      <span className="text-xs text-content-muted">{sys.action}</span>
                    </div>
                    {sys.packages_affected.length > 0 ? (
                      <div className="text-sm space-y-1">
                        {sys.packages_affected.map((pkg) => (
                          <div key={pkg.name} className="flex items-center gap-2 text-content">
                            <span className="font-medium">{pkg.name}</span>
                            <span className="text-content-subtle">{pkg.from_version}</span>
                            <span className="text-content-subtle">→</span>
                            <span className={pkg.type === 'security' ? 'text-red-400' : 'text-orange-400'}>
                              {pkg.to_version}
                            </span>
                            {pkg.type === 'security' && (
                              <Badge variant="danger">security</Badge>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-sm text-content-subtle">
                        {sys.installed_packages !== undefined
                          ? `${sys.installed_packages} packages installed`
                          : 'No changes'}
                      </div>
                    )}
                  </div>
                ))}
              </div>
              <div className="mt-4 flex justify-end gap-2">
                <Button variant="outline" onClick={() => setDryRunResult(null)}>
                  Close
                </Button>
              </div>
            </div>
          </div>
        )}

        <ConfirmModal
          open={!!confirmDelete}
          onClose={() => setConfirmDelete(null)}
          onConfirm={() => {
            if (confirmDelete) {
              handleDelete(confirmDelete);
              setConfirmDelete(null);
            }
          }}
          title="Delete Job"
          message={confirmDelete ? `Are you sure you want to delete "${confirmDelete.name}"? This action cannot be undone.` : ''}
          confirmLabel="Delete"
          variant="danger"
        />
    </MainLayout>
  );
};

export default ScheduledJobs;
