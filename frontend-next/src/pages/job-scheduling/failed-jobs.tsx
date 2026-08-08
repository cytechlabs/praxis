import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { RefreshCw, AlertTriangle, RotateCcw, ChevronDown, ChevronUp, Undo2 } from 'lucide-react';
import { fetchFailedJobs, runJob, rollbackJobHistory, JobHistoryItem, JobHistoryResponse } from '@/services/jobService';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { PageHeader, Button, StatCard, Card, Badge, EmptyState, ConfirmModal } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { formatJobResultDetail } from '@/utils/jobResults';

const getDuration = (start: string | null, end: string | null) => {
  if (!start || !end) return '-';
  const ms = new Date(end).getTime() - new Date(start).getTime();
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
};

const FailedJobs = () => {
  const formatTimestamp = useFormatTimestamp();
  const [failedJobs, setFailedJobs] = useState<JobHistoryItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [retryingId, setRetryingId] = useState<number | null>(null);
  const [rollingBackId, setRollingBackId] = useState<number | null>(null);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [page, setPage] = useState(0);
  const limit = 25;
  const [confirmRollback, setConfirmRollback] = useState<JobHistoryItem | null>(null);

  const loadFailedJobs = useCallback(async () => {
    setLoading(true);
    try {
      const response: JobHistoryResponse = await fetchFailedJobs(limit, page * limit);
      setFailedJobs(response.history);
      setTotal(response.total);
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Failed to load failed jobs');
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    loadFailedJobs();
  }, [loadFailedJobs]);

  const toggleExpand = (id: number) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const handleRetry = async (item: JobHistoryItem) => {
    setRetryingId(item.id);
    try {
      await runJob(item.job_id);
      toast.success('Job re-triggered successfully');
      loadFailedJobs();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to retry job');
    } finally {
      setRetryingId(null);
    }
  };

  const handleRollback = async (item: JobHistoryItem) => {
    setRollingBackId(item.id);
    try {
      const result = await rollbackJobHistory(item.id);
      if (result.total_failed > 0) {
        toast.error(
          `Rolled back ${result.total_rolled_back} packages, ${result.total_failed} system(s) failed`
        );
      } else {
        toast.success(
          `Rolled back ${result.total_rolled_back} packages across ${result.total_systems} system(s)`
        );
      }
      loadFailedJobs();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Rollback failed');
    } finally {
      setRollingBackId(null);
    }
  };

  // Stats
  const totalFailures = total;
  const recent24h = failedJobs.filter((item) => {
    if (!item.start_time) return false;
    const diff = Date.now() - new Date(item.start_time).getTime();
    return diff < 24 * 60 * 60 * 1000;
  }).length;
  const uniqueJobs = new Set(failedJobs.map((item) => item.job_id)).size;

  const totalPages = Math.ceil(total / limit);

  return (
    <MainLayout>
        <Head>
          <title>Failed Jobs | Praxis</title>
        </Head>
        <PageHeader
          title="Failed Jobs"
          actions={
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                icon={<RefreshCw className="w-4 h-4" />}
                onClick={() => loadFailedJobs()}
              >
                Refresh
              </Button>
              <HelpLink slug="jobs-and-scheduling" />
            </div>
          }
        />

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <StatCard label="Total Failures" value={totalFailures} icon={<AlertTriangle className="w-3 h-3" />} />
          <StatCard label="Recent (24h)" value={recent24h} />
          <StatCard label="Unique Jobs" value={uniqueJobs} />
        </div>

        {/* Table */}
        <Card>
          <div className="p-6">
            {/* Table Header */}
            <div className="grid grid-cols-7 gap-4 p-4 bg-surface-raised border-b border-border font-medium text-content text-sm rounded-t-lg">
              <div>Job Name</div>
              <div>Job Type</div>
              <div>Systems Failed</div>
              <div>Started</div>
              <div>Duration</div>
              <div>Error</div>
              <div>Actions</div>
            </div>

            {/* Loading */}
            {loading && <div className="p-4 text-content-muted">Loading...</div>}

            {/* Empty State */}
            {!loading && failedJobs.length === 0 && (
              <EmptyState
                icon={<AlertTriangle className="w-6 h-6 text-green-500" />}
                title="No failed jobs found"
                description="All jobs are running smoothly - great news!"
              />
            )}

            {/* Table Rows */}
            {!loading &&
              failedJobs.map((item) => (
                <React.Fragment key={item.id}>
                  <div className="grid grid-cols-7 gap-4 p-4 border-b border-border text-content hover:bg-white/[0.03]/50 text-sm items-center">
                    <div className="truncate font-medium" title={item.job_name}>{item.job_name}</div>
                    <div>
                      <Badge variant="danger">failed</Badge>
                    </div>
                    <div className="text-red-400 font-medium">{item.systems_failed} / {item.systems_targeted}</div>
                    <div>{item.start_time ? formatTimestamp(item.start_time) : '-'}</div>
                    <div>{getDuration(item.start_time, item.end_time)}</div>
                    <div className="truncate text-red-300" title={item.error_message || undefined}>
                      {item.error_message ? item.error_message.substring(0, 50) + (item.error_message.length > 50 ? '...' : '') : '-'}
                    </div>
                    <div className="flex items-center gap-1">
                      {/* PRA-270: retry is non-destructive; quiet neutral icon
                          action instead of a repeated solid-red button. */}
                      <Button
                        variant="ghost"
                        size="sm"
                        iconOnly
                        aria-label="Retry job"
                        onClick={() => handleRetry(item)}
                        disabled={retryingId === item.id}
                        loading={retryingId === item.id}
                        icon={retryingId !== item.id ? <RotateCcw className="w-3 h-3" /> : undefined}
                        title="Retry Job"
                      />
                      {(item.job_type === 'update' || item.job_type === 'security_update') &&
                        item.systems_completed > 0 && (
                          <button
                            onClick={() => setConfirmRollback(item)}
                            disabled={rollingBackId === item.id}
                            className="bg-orange-700 hover:bg-orange-600 text-white px-3 py-1.5 rounded text-sm flex items-center gap-1 disabled:opacity-50"
                            aria-label="Rollback completed package updates" title="Rollback completed package updates"
                          >
                            {rollingBackId === item.id ? (
                              <RefreshCw className="w-3 h-3 animate-spin" />
                            ) : (
                              <Undo2 className="w-3 h-3" />
                            )}
                          </button>
                        )}
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => toggleExpand(item.id)}
                        title="Toggle Details"
                      >
                        {expandedId === item.id ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                      </Button>
                    </div>
                  </div>
                  {expandedId === item.id && (
                    <div className="col-span-7 bg-white/[0.02] p-4 border-t border-border/50">
                      <div className="grid grid-cols-3 gap-4 mb-3">
                        <div><span className="text-content-muted text-xs">Systems Targeted</span><p className="text-content">{item.systems_targeted}</p></div>
                        <div><span className="text-content-muted text-xs">Completed</span><p className="text-green-400">{item.systems_completed}</p></div>
                        <div><span className="text-content-muted text-xs">Failed</span><p className="text-red-400">{item.systems_failed}</p></div>
                      </div>
                      {item.error_message && (
                        <div className="mb-3">
                          <span className="text-content-muted text-xs block mb-1">Error Message</span>
                          <p className="text-red-300 text-sm bg-surface-raised rounded p-2 border border-border/50">{item.error_message}</p>
                        </div>
                      )}
                      {item.result && (
                        <div>
                          <span className="text-content-muted text-xs block mb-1">Detailed Results</span>
                          <pre className="text-content text-xs bg-surface-raised rounded p-2 border border-border/50 overflow-x-auto max-h-40 overflow-y-auto">
                            {formatJobResultDetail(item.result)}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </React.Fragment>
              ))}

            {/* Pagination */}
            {!loading && totalPages > 1 && (
              <div className="flex items-center justify-between p-4 border-t border-border">
                <span className="text-sm text-content-muted">
                  Showing {page * limit + 1}-{Math.min((page + 1) * limit, total)} of {total}
                </span>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage(page - 1)}
                    disabled={page === 0}
                  >
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage(page + 1)}
                    disabled={page >= totalPages - 1}
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </div>
        </Card>

        <ConfirmModal
          open={!!confirmRollback}
          onClose={() => setConfirmRollback(null)}
          onConfirm={() => {
            if (confirmRollback) {
              handleRollback(confirmRollback);
              setConfirmRollback(null);
            }
          }}
          title="Rollback Packages"
          message={confirmRollback ? `Roll back packages updated by "${confirmRollback.job_name}"? This will downgrade packages to their pre-update versions on affected systems.` : ''}
          confirmLabel="Rollback"
          variant="warning"
        />
    </MainLayout>
  );
};

export default FailedJobs;
