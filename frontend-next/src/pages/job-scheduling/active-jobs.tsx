import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { RefreshCw, XCircle, Activity, Server, Clock } from 'lucide-react';
import { fetchActiveJobs, cancelJob, Job } from '@/services/jobService';
import { fetchAllSystems, fetchGroups } from '@/services/systemService';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { PageHeader, Button, StatCard, Card, EmptyState, ConfirmModal } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';

interface ActiveJob extends Job {
  current_run?: {
    history_id: number;
    start_time: string | null;
    systems_targeted: number;
    systems_completed: number;
    systems_failed: number;
    progress_pct: number;
  };
}

const getElapsedTime = (startTime: string | null) => {
  if (!startTime) return '-';
  const start = new Date(startTime).getTime();
  const now = Date.now();
  const diff = Math.floor((now - start) / 1000);
  if (diff < 60) return `${diff}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s`;
  return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m`;
};

const ActiveJobs = () => {
  const formatTimestamp = useFormatTimestamp();
  const [activeJobs, setActiveJobs] = useState<ActiveJob[]>([]);
  const [loading, setLoading] = useState(false);
  const [cancellingId, setCancellingId] = useState<number | null>(null);
  const [systems, setSystems] = useState<{ id: number; hostname: string }[]>([]);
  const [groups, setGroups] = useState<{ id: number; name: string }[]>([]);
  const [confirmCancelJob, setConfirmCancelJob] = useState<ActiveJob | null>(null);

  const loadActiveJobs = useCallback(async () => {
    try {
      const jobs = (await fetchActiveJobs()) as ActiveJob[];
      setActiveJobs(jobs);
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Failed to load active jobs');
    }
  }, []);

  const loadSystemsAndGroups = useCallback(async () => {
    try {
      const [systemsData, groupsData] = await Promise.all([fetchAllSystems(), fetchGroups()]);
      setSystems(systemsData.map((s) => ({ id: s.id, hostname: s.hostname })));
      setGroups(groupsData.map((g) => ({ id: g.id, name: g.name })));
    } catch {
      // Systems/groups load is best-effort
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    loadActiveJobs().finally(() => setLoading(false));
    const interval = setInterval(loadActiveJobs, 5000);
    return () => clearInterval(interval);
  }, [loadActiveJobs]);

  useEffect(() => {
    loadSystemsAndGroups();
  }, [loadSystemsAndGroups]);

  const handleCancel = async (jobId: number) => {
    setCancellingId(jobId);
    try {
      await cancelJob(jobId);
      toast.success('Job cancelled');
      loadActiveJobs();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to cancel job');
    } finally {
      setCancellingId(null);
    }
  };

  const getTargetDisplay = (job: ActiveJob) => {
    if (job.target_type === 'all') return 'All Systems';
    if (job.target_type === 'group') {
      const names = (job.target_ids || []).map((id) => groups.find((g) => g.id === id)?.name || `Group ${id}`);
      return names.join(', ') || 'No groups';
    }
    const names = (job.target_ids || []).map((id) => systems.find((s) => s.id === id)?.hostname || `System ${id}`);
    return names.join(', ') || 'No systems';
  };

  // Stats
  const runningCount = activeJobs.length;
  const systemsInUse = activeJobs.reduce((sum, job) => sum + (job.current_run?.systems_targeted || 0), 0);
  const longestElapsed = activeJobs.reduce((longest, job) => {
    const startTime = job.current_run?.start_time || job.last_run;
    if (!startTime) return longest;
    const elapsed = Date.now() - new Date(startTime).getTime();
    return elapsed > longest ? elapsed : longest;
  }, 0);
  const longestElapsedDisplay = longestElapsed > 0 ? getElapsedTime(new Date(Date.now() - longestElapsed).toISOString()) : '-';

  return (
    <MainLayout>
        <Head>
          <title>Active Jobs | Praxis</title>
        </Head>
        <PageHeader
          title="Active Jobs"
          actions={
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                icon={<RefreshCw className="w-4 h-4" />}
                onClick={() => loadActiveJobs()}
              >
                Refresh
              </Button>
              <HelpLink slug="jobs-and-scheduling" />
            </div>
          }
        />

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <StatCard label="Running Jobs" value={runningCount} icon={<Activity className="w-3 h-3" />} />
          <StatCard label="Systems In Use" value={systemsInUse} icon={<Server className="w-3 h-3" />} />
          <StatCard label="Elapsed Time" value={longestElapsedDisplay} icon={<Clock className="w-3 h-3" />} />
        </div>

        {/* Table */}
        <Card>
          <div className="p-6">
            {/* Table Header */}
            <div className="grid grid-cols-8 gap-4 p-4 bg-surface-raised border-b border-border font-medium text-content text-sm rounded-t-lg">
              <div>Job Name</div>
              <div>Job Type</div>
              <div>Target</div>
              <div>Progress</div>
              <div>Systems</div>
              <div>Started</div>
              <div>Elapsed</div>
              <div>Actions</div>
            </div>

            {/* Loading */}
            {loading && <div className="p-4 text-content-muted">Loading...</div>}

            {/* Empty State */}
            {!loading && activeJobs.length === 0 && (
              <EmptyState
                icon={<Activity className="w-6 h-6 text-content-subtle" />}
                title="No jobs currently running"
              />
            )}

            {/* Table Rows */}
            {!loading &&
              activeJobs.map((job) => {
                const progressPct = job.current_run?.progress_pct || 0;
                const startTime = job.current_run?.start_time || job.last_run;
                const systemsCompleted = job.current_run?.systems_completed || 0;
                const systemsTargeted = job.current_run?.systems_targeted || 0;

                return (
                  <div key={job.id} className="grid grid-cols-8 gap-4 p-4 border-b border-border text-content hover:bg-white/[0.03]/50 text-sm items-center">
                    <div className="truncate font-medium" title={job.name}>{job.name}</div>
                    <div className="capitalize">{job.job_type.replace('_', ' ')}</div>
                    <div className="truncate" title={getTargetDisplay(job)}>{getTargetDisplay(job)}</div>
                    <div>
                      <div className="w-full bg-surface-overlay rounded-full h-2">
                        <div className="bg-red-600 h-2 rounded-full" style={{ width: `${progressPct}%` }} />
                      </div>
                      <span className="text-xs text-content-muted">{progressPct}%</span>
                    </div>
                    <div>{systemsCompleted}/{systemsTargeted}</div>
                    <div>{startTime ? formatTimestamp(startTime) : '-'}</div>
                    <div>{getElapsedTime(startTime || null)}</div>
                    <div>
                      {/* PRA-270: quiet icon action; Signal Red is on the cancel
                          ConfirmModal, not the repeated row button. */}
                      <Button
                        variant="ghost"
                        size="sm"
                        iconOnly
                        aria-label="Cancel job"
                        title="Cancel job"
                        onClick={() => setConfirmCancelJob(job)}
                        disabled={cancellingId === job.id}
                        loading={cancellingId === job.id}
                        icon={cancellingId !== job.id ? <XCircle className="w-3 h-3" /> : undefined}
                      />
                    </div>
                  </div>
                );
              })}
          </div>
        </Card>

        <ConfirmModal
          open={!!confirmCancelJob}
          onClose={() => setConfirmCancelJob(null)}
          onConfirm={() => {
            if (confirmCancelJob) {
              handleCancel(confirmCancelJob.id);
              setConfirmCancelJob(null);
            }
          }}
          title="Cancel Job"
          message="Are you sure you want to cancel this job?"
          confirmLabel="Cancel Job"
          variant="danger"
        />
    </MainLayout>
  );
};

export default ActiveJobs;
