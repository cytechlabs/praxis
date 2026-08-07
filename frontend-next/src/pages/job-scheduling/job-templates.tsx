import React, { useState, useEffect } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { Package, Shield, ClipboardCheck, Search, Layers, Users, Plus, Play, Trash2, X } from 'lucide-react';
import { createJob, fetchJobs, deleteJob, Job, JobCreate } from '@/services/jobService';
import { fetchAllSystems, fetchGroups } from '@/services/systemService';
import { fetchTags, Tag as TagType } from '@/services/tagService';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { PageHeader, Button, Badge, statusToBadgeVariant, Card, EmptyState, ConfirmModal } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';

// --- Types ---

interface JobTemplate {
  id: string;
  name: string;
  description: string;
  icon: React.ReactNode;
  job_type: string;
  target_type: string;
  target_ids?: number[];
  package_filter?: { names?: string[]; keywords?: string[]; security_only?: boolean };
  is_builtin: boolean;
}

// --- Built-in templates ---

const BUILTIN_TEMPLATES: JobTemplate[] = [
  {
    id: 'update-all',
    name: 'Update All Packages',
    description: 'Update all packages on all systems to their latest versions',
    icon: <Package size={24} />,
    job_type: 'update',
    target_type: 'all',
    is_builtin: true,
  },
  {
    id: 'security-updates',
    name: 'Security Updates Only',
    description: 'Apply only security-related updates across all systems',
    icon: <Shield size={24} />,
    job_type: 'security_update',
    target_type: 'all',
    package_filter: { security_only: true },
    is_builtin: true,
  },
  {
    id: 'system-audit',
    name: 'Full System Audit',
    description: 'Run a comprehensive audit on all managed systems',
    icon: <ClipboardCheck size={24} />,
    job_type: 'audit',
    target_type: 'all',
    is_builtin: true,
  },
  {
    id: 'package-scan',
    name: 'Package Inventory Scan',
    description: 'Scan and refresh package inventory across all systems',
    icon: <Search size={24} />,
    job_type: 'package_scan',
    target_type: 'all',
    is_builtin: true,
  },
  {
    id: 'update-specific',
    name: 'Update Specific Packages',
    description: 'Update targeted packages by name or keyword filter',
    icon: <Layers size={24} />,
    job_type: 'update',
    target_type: 'all',
    package_filter: { names: [], keywords: [] },
    is_builtin: true,
  },
  {
    id: 'group-update',
    name: 'Group Update',
    description: 'Update all packages for specific system groups',
    icon: <Users size={24} />,
    job_type: 'update',
    target_type: 'group',
    target_ids: [],
    is_builtin: true,
  },
];

// --- Helpers ---

const getJobTypeBadge = (type: string) => {
  const labels: Record<string, string> = {
    update: 'Update',
    security_update: 'Security',
    audit: 'Audit',
    package_scan: 'Scan',
  };
  return labels[type] || type;
};

interface ScheduleConfig {
  frequency: string;
  time: string;
  dayOfWeek: string;
  dayOfMonth: string;
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

const ordinal = (n: number): string => {
  const s = ['th', 'st', 'nd', 'rd'];
  const v = n % 100;
  return n + (s[(v - 20) % 10] || s[v] || s[0]);
};

const defaultFormData = (): JobCreate => ({
  name: '',
  description: '',
  job_type: 'update',
  is_recurring: false,
  schedule: '',
  target_type: 'all',
  target_ids: [],
  package_filter: undefined,
  tag_match_logic: 'or',
});

// --- Component ---

const JobTemplates = () => {
  const formatTimestamp = useFormatTimestamp();
  const [showForm, setShowForm] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<JobTemplate | null>(null);
  const [customTemplates, setCustomTemplates] = useState<Job[]>([]);
  const [systems, setSystems] = useState<{ id: number; hostname: string }[]>([]);
  const [groups, setGroups] = useState<{ id: number; name: string }[]>([]);
  const [tags, setTags] = useState<{ id: number; name: string; color: string }[]>([]);
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formData, setFormData] = useState<JobCreate>(defaultFormData());
  const [scheduleConfig, setScheduleConfig] = useState<ScheduleConfig>({ ...defaultSchedule });
  const [confirmDelete, setConfirmDelete] = useState<Job | null>(null);

  // Package filter local state
  const [packageNames, setPackageNames] = useState('');
  const [packageKeywords, setPackageKeywords] = useState('');
  const [securityOnly, setSecurityOnly] = useState(false);

  // Load systems, groups, and saved jobs on mount
  useEffect(() => {
    const load = async () => {
      try {
        const [systemsData, groupsData, jobsData, tagsData] = await Promise.all([
          fetchAllSystems(),
          fetchGroups(),
          fetchJobs(),
          fetchTags(),
        ]);
        setSystems(systemsData.map((s: { id: number; hostname: string }) => ({ id: s.id, hostname: s.hostname })));
        setGroups(groupsData.map((g: { id: number; name: string }) => ({ id: g.id, name: g.name })));
        setCustomTemplates(jobsData.jobs || []);
        setTags(tagsData.map((t: TagType) => ({ id: t.id, name: t.name, color: t.color })));
      } catch (err) {
        console.error('Failed to load data:', err);
      }
    };
    load();
  }, []);

  const openFormForTemplate = (template: JobTemplate) => {
    const now = formatTimestamp(new Date());
    setSelectedTemplate(template);

    const pf = template.package_filter;
    setPackageNames(pf?.names?.join(', ') || '');
    setPackageKeywords(pf?.keywords?.join(', ') || '');
    setSecurityOnly(pf?.security_only || false);

    setFormData({
      name: `${template.name} - ${now}`,
      description: template.description,
      job_type: template.job_type,
      is_recurring: false,
      schedule: '',
      target_type: template.target_type,
      target_ids: template.target_ids || [],
      package_filter: template.package_filter,
    });
    setShowForm(true);
  };

  const openFormForJob = (job: Job) => {
    const now = formatTimestamp(new Date());
    setSelectedTemplate(null);

    const pf = job.package_filter;
    setPackageNames(pf?.names?.join(', ') || '');
    setPackageKeywords(pf?.keywords?.join(', ') || '');
    setSecurityOnly(pf?.security_only || false);

    setFormData({
      name: `${job.name} - ${now}`,
      description: job.description || '',
      job_type: job.job_type,
      is_recurring: job.is_recurring,
      schedule: job.schedule || '',
      target_type: job.target_type,
      target_ids: job.target_ids || [],
      package_filter: job.package_filter || undefined,
    });
    setShowForm(true);
  };

  const openBlankForm = () => {
    setSelectedTemplate(null);
    setFormData(defaultFormData());
    setPackageNames('');
    setPackageKeywords('');
    setSecurityOnly(false);
    setScheduleConfig({ ...defaultSchedule });
    setShowForm(true);
  };

  const closeForm = () => {
    setShowForm(false);
    setSelectedTemplate(null);
  };

  const buildPackageFilter = () => {
    const names = packageNames.split(',').map(s => s.trim()).filter(Boolean);
    const keywords = packageKeywords.split(',').map(s => s.trim()).filter(Boolean);
    if (!names.length && !keywords.length && !securityOnly) return undefined;
    return {
      ...(names.length ? { names } : {}),
      ...(keywords.length ? { keywords } : {}),
      ...(securityOnly ? { security_only: true } : {}),
    };
  };

  const handleSubmit = async () => {
    if (!formData.name.trim()) {
      toast.error('Job name is required');
      return;
    }

    setSubmitting(true);
    try {
      const payload: JobCreate = {
        name: formData.name.trim(),
        description: formData.description || undefined,
        job_type: formData.job_type,
        is_recurring: formData.is_recurring,
        schedule: formData.is_recurring ? scheduleToCron(scheduleConfig) : undefined,
        target_type: formData.target_type,
        target_ids: (formData.target_type === 'system' || formData.target_type === 'group' || formData.target_type === 'tag') && formData.target_ids?.length
          ? formData.target_ids
          : undefined,
        package_filter: buildPackageFilter(),
        tag_match_logic: formData.target_type === 'tag' ? (formData.tag_match_logic || 'or') : undefined,
      };

      await createJob(payload);
      toast.success('Job created successfully');
      closeForm();

      // Refresh custom templates
      const jobsData = await fetchJobs();
      setCustomTemplates(jobsData.jobs || []);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to create job';
      toast.error(message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteCustomTemplate = async (jobId: number) => {
    try {
      setLoading(true);
      await deleteJob(jobId);
      toast.success('Template deleted');
      setCustomTemplates(prev => prev.filter(j => j.id !== jobId));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to delete template';
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  const toggleTargetId = (id: number) => {
    setFormData(prev => {
      const current = prev.target_ids || [];
      const next = current.includes(id) ? current.filter(i => i !== id) : [...current, id];
      return { ...prev, target_ids: next };
    });
  };

  // --- Render ---

  return (
    <MainLayout>
        <Head>
          <title>Job Templates | Praxis</title>
        </Head>
        <PageHeader
          title="Job Templates"
          actions={
            <div className="flex items-center gap-2">
              <Button
                variant="primary"
                icon={<Plus size={18} />}
                onClick={openBlankForm}
              >
                Create Custom Template
              </Button>
              <HelpLink slug="jobs-and-scheduling" />
            </div>
          }
        />

        {/* Built-in Templates */}
        <h2 className="text-lg font-medium text-gray-200 mb-3">Built-in Templates</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
          {BUILTIN_TEMPLATES.map(template => (
            <Card
              key={template.id}
              hover
              onClick={() => openFormForTemplate(template)}
              className="cursor-pointer"
            >
              <div className="p-5">
                <div className="text-red-500 mb-3">{template.icon}</div>
                <h3 className="text-gray-200 font-medium mb-1">{template.name}</h3>
                <p className="text-gray-400 text-sm mb-3">{template.description}</p>
                <div className="flex items-center gap-2">
                  <Badge variant="neutral">{getJobTypeBadge(template.job_type)}</Badge>
                  <Badge variant="neutral">
                    {template.target_type === 'all' ? 'All Systems' : template.target_type === 'group' ? 'Group' : template.target_type === 'tag' ? 'Tags' : template.target_type}
                  </Badge>
                </div>
              </div>
            </Card>
          ))}
        </div>

        {/* Custom / Saved Templates */}
        <h2 className="text-lg font-medium text-gray-200 mb-3">Saved Jobs (Use as Templates)</h2>
        {customTemplates.length === 0 ? (
          <Card className="mb-8">
            <EmptyState
              title="No saved jobs yet"
              description="Create a job to use it as a reusable template."
            />
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
            {customTemplates.map(job => (
              <Card key={job.id}>
                <div className="p-5">
                  <div className="text-red-500 mb-3">
                    <Package size={24} />
                  </div>
                  <h3 className="text-gray-200 font-medium mb-1">{job.name}</h3>
                  <p className="text-gray-400 text-sm mb-3">{job.description || 'No description'}</p>
                  <div className="flex items-center gap-2 mb-4">
                    <Badge variant="neutral">{getJobTypeBadge(job.job_type)}</Badge>
                    <Badge variant="neutral">
                      {job.target_type === 'all' ? 'All Systems' : job.target_type === 'group' ? 'Group' : job.target_type === 'tag' ? 'Tags' : job.target_type}
                    </Badge>
                    <Badge variant={statusToBadgeVariant(job.status)}>{job.status}</Badge>
                  </div>
                  <div className="flex gap-2">
                    {/* PRA-270: de-emphasize the repeated card action to secondary
                        so the grid isn't a wall of primary buttons (label kept -
                        cards have room, unlike dense table rows). */}
                    <Button
                      variant="secondary"
                      size="sm"
                      icon={<Play size={14} />}
                      onClick={() => openFormForJob(job)}
                    >
                      Use Template
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      icon={<Trash2 size={14} />}
                      onClick={() => setConfirmDelete(job)}
                      disabled={loading}
                    >
                      Delete
                    </Button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}

        {/* Form Modal */}
        {showForm && (
          <div className="fixed inset-0 bg-[#0c0c0f]/70 backdrop-blur-sm flex items-center justify-center z-50">
            <div className="bg-gray-950 border border-gray-800 rounded-lg p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-lg font-medium text-gray-200">
                  {selectedTemplate ? `Create Job from: ${selectedTemplate.name}` : 'Create Custom Job'}
                </h2>
                <button onClick={closeForm} className="text-gray-400 hover:text-gray-200 transition-colors">
                  <X size={20} />
                </button>
              </div>

              {/* Name */}
              <div className="mb-4">
                <label className="block text-sm text-gray-400 mb-1">Job Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={e => setFormData(prev => ({ ...prev, name: e.target.value }))}
                  className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 w-full focus:outline-none focus:border-red-600"
                  placeholder="Enter job name"
                />
              </div>

              {/* Description */}
              <div className="mb-4">
                <label className="block text-sm text-gray-400 mb-1">Description</label>
                <textarea
                  value={formData.description || ''}
                  onChange={e => setFormData(prev => ({ ...prev, description: e.target.value }))}
                  className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 w-full focus:outline-none focus:border-red-600"
                  rows={3}
                  placeholder="Optional description"
                />
              </div>

              {/* Job Type */}
              <div className="mb-4">
                <label className="block text-sm text-gray-400 mb-1">Job Type</label>
                <select
                  value={formData.job_type}
                  onChange={e => setFormData(prev => ({ ...prev, job_type: e.target.value }))}
                  className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 w-full focus:outline-none focus:border-red-600"
                >
                  <option value="update">Update</option>
                  <option value="security_update">Security Update</option>
                  <option value="audit">Audit</option>
                  <option value="package_scan">Package Scan</option>
                </select>
              </div>

              {/* Recurring Toggle */}
              <div className="mb-4">
                <label className="flex items-center gap-3 cursor-pointer">
                  <div
                    onClick={() => setFormData(prev => ({ ...prev, is_recurring: !prev.is_recurring }))}
                    className={`relative w-10 h-5 rounded-full transition-colors ${
                      formData.is_recurring ? 'bg-red-600' : 'bg-gray-700'
                    }`}
                  >
                    <div
                      className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full transition-transform ${
                        formData.is_recurring ? 'translate-x-5' : ''
                      }`}
                    />
                  </div>
                  <span className="text-sm text-gray-400">Recurring Job</span>
                </label>
              </div>

              {/* Schedule */}
              {formData.is_recurring && (
                <div className="mb-4">
                  <label className="block text-sm text-gray-400 mb-1">Schedule</label>
                  <div className="flex items-center gap-2 flex-wrap">
                    <select
                      value={scheduleConfig.frequency}
                      onChange={(e) => setScheduleConfig({ ...scheduleConfig, frequency: e.target.value })}
                      className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 focus:outline-none focus:border-red-600"
                    >
                      <option value="daily">Every day</option>
                      <option value="weekly">Every week on</option>
                      <option value="monthly">Every month on the</option>
                    </select>
                    {scheduleConfig.frequency === 'weekly' && (
                      <select
                        value={scheduleConfig.dayOfWeek}
                        onChange={(e) => setScheduleConfig({ ...scheduleConfig, dayOfWeek: e.target.value })}
                        className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 focus:outline-none focus:border-red-600"
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
                        className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 focus:outline-none focus:border-red-600"
                      >
                        {Array.from({ length: 28 }, (_, i) => (
                          <option key={i + 1} value={String(i + 1)}>{ordinal(i + 1)}</option>
                        ))}
                      </select>
                    )}
                    <span className="text-gray-400 text-sm">at</span>
                    <input
                      type="time"
                      value={scheduleConfig.time}
                      onChange={(e) => setScheduleConfig({ ...scheduleConfig, time: e.target.value })}
                      className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 focus:outline-none focus:border-red-600"
                    />
                  </div>
                </div>
              )}

              {/* Target Type */}
              <div className="mb-4">
                <label className="block text-sm text-gray-400 mb-1">Target Type</label>
                <select
                  value={formData.target_type}
                  onChange={e => setFormData(prev => ({ ...prev, target_type: e.target.value, target_ids: [] }))}
                  className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 w-full focus:outline-none focus:border-red-600"
                >
                  <option value="all">All Systems</option>
                  <option value="system">Specific Systems</option>
                  <option value="group">System Groups</option>
                  <option value="tag">Tags</option>
                </select>
              </div>

              {/* System Selection */}
              {formData.target_type === 'system' && (
                <div className="mb-4">
                  <label className="block text-sm text-gray-400 mb-1">Select Systems</label>
                  <div className="bg-gray-950 border border-gray-800 rounded-lg p-3 max-h-40 overflow-y-auto">
                    {systems.length === 0 ? (
                      <p className="text-gray-500 text-sm">No systems available</p>
                    ) : (
                      systems.map(system => (
                        <label key={system.id} className="flex items-center gap-2 py-1 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={formData.target_ids?.includes(system.id) || false}
                            onChange={() => toggleTargetId(system.id)}
                            className="accent-red-600"
                          />
                          <span className="text-gray-300 text-sm">{system.hostname}</span>
                        </label>
                      ))
                    )}
                  </div>
                </div>
              )}

              {/* Group Selection */}
              {formData.target_type === 'group' && (
                <div className="mb-4">
                  <label className="block text-sm text-gray-400 mb-1">Select Groups</label>
                  <div className="bg-gray-950 border border-gray-800 rounded-lg p-3 max-h-40 overflow-y-auto">
                    {groups.length === 0 ? (
                      <p className="text-gray-500 text-sm">No groups available</p>
                    ) : (
                      groups.map(group => (
                        <label key={group.id} className="flex items-center gap-2 py-1 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={formData.target_ids?.includes(group.id) || false}
                            onChange={() => toggleTargetId(group.id)}
                            className="accent-red-600"
                          />
                          <span className="text-gray-300 text-sm">{group.name}</span>
                        </label>
                      ))
                    )}
                  </div>
                </div>
              )}

              {/* Tag Selection */}
              {formData.target_type === 'tag' && (
                <div className="mb-4">
                  <label className="block text-sm text-gray-400 mb-1">Select Tags</label>
                  <div className="bg-gray-950 border border-gray-800 rounded-lg p-3 max-h-40 overflow-y-auto">
                    {tags.length === 0 ? (
                      <p className="text-gray-500 text-sm">No tags available</p>
                    ) : (
                      tags.map(tag => (
                        <label key={tag.id} className="flex items-center gap-2 py-1 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={formData.target_ids?.includes(tag.id) || false}
                            onChange={() => toggleTargetId(tag.id)}
                            className="accent-red-600"
                          />
                          <span className="w-3 h-3 rounded-full inline-block flex-shrink-0" style={{ backgroundColor: tag.color }} />
                          <span className="text-gray-300 text-sm">{tag.name}</span>
                        </label>
                      ))
                    )}
                  </div>
                </div>
              )}

              {/* Tag Match Logic */}
              {formData.target_type === 'tag' && (formData.target_ids?.length || 0) > 1 && (
                <div className="mb-4">
                  <label className="block text-sm text-gray-400 mb-1">Match Logic</label>
                  <div className="flex gap-3">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="tagLogic"
                        value="or"
                        checked={formData.tag_match_logic !== 'and'}
                        onChange={() => setFormData(prev => ({ ...prev, tag_match_logic: 'or' }))}
                        className="accent-red-600"
                      />
                      <span className="text-gray-300 text-sm">Any tag (OR)</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="tagLogic"
                        value="and"
                        checked={formData.tag_match_logic === 'and'}
                        onChange={() => setFormData(prev => ({ ...prev, tag_match_logic: 'and' }))}
                        className="accent-red-600"
                      />
                      <span className="text-gray-300 text-sm">All tags (AND)</span>
                    </label>
                  </div>
                </div>
              )}

              {/* Package Filter (for update / security_update types) */}
              {(formData.job_type === 'update' || formData.job_type === 'security_update') && (
                <div className="mb-4 border border-gray-700 rounded-lg p-4">
                  <h3 className="text-sm font-medium text-gray-300 mb-3">Package Filter (Optional)</h3>

                  <div className="mb-3">
                    <label className="block text-sm text-gray-400 mb-1">Package Names (comma-separated)</label>
                    <input
                      type="text"
                      value={packageNames}
                      onChange={e => setPackageNames(e.target.value)}
                      className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 w-full focus:outline-none focus:border-red-600"
                      placeholder="e.g. nginx, openssl, curl"
                    />
                  </div>

                  <div className="mb-3">
                    <label className="block text-sm text-gray-400 mb-1">Keywords (comma-separated)</label>
                    <input
                      type="text"
                      value={packageKeywords}
                      onChange={e => setPackageKeywords(e.target.value)}
                      className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 w-full focus:outline-none focus:border-red-600"
                      placeholder="e.g. lib, python, security"
                    />
                  </div>

                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={securityOnly}
                      onChange={e => setSecurityOnly(e.target.checked)}
                      className="accent-red-600"
                    />
                    <span className="text-sm text-gray-400">Security updates only</span>
                  </label>
                </div>
              )}

              {/* Actions */}
              <div className="flex justify-end gap-3 mt-6">
                <Button variant="ghost" onClick={closeForm}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  onClick={handleSubmit}
                  disabled={submitting}
                  loading={submitting}
                >
                  Create Job
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
              handleDeleteCustomTemplate(confirmDelete.id);
              setConfirmDelete(null);
            }
          }}
          title="Delete Template"
          message={confirmDelete ? `Are you sure you want to delete "${confirmDelete.name}"? This action cannot be undone.` : ''}
          confirmLabel="Delete"
          variant="danger"
        />
    </MainLayout>
  );
};

export default JobTemplates;
