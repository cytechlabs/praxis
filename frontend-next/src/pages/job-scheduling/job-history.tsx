import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { RefreshCw, Filter, CheckCircle, XCircle, Clock, AlertTriangle } from 'lucide-react';
import { fetchAllJobHistory, JobHistoryItem, JobHistoryResponse } from '@/services/jobService';
import ExportButton from '@/components/ExportButton';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { PageHeader, Button, StatCard, Card, Badge, statusToBadgeVariant, EmptyState, Select } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { humanizeStatus, humanizeLabel } from '@/utils/humanize';
import { summarizeJobResult } from '@/utils/jobResults';

const getDuration = (start: string | null, end: string | null) => {
  if (!start || !end) return '-';
  const ms = new Date(end).getTime() - new Date(start).getTime();
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
};

const getStatusIcon = (status: string) => {
  switch (status) {
    case 'completed': return <CheckCircle className="w-3 h-3" />;
    case 'failed': return <XCircle className="w-3 h-3" />;
    case 'running': return <Clock className="w-3 h-3" />;
    case 'cancelled': return <AlertTriangle className="w-3 h-3" />;
    default: return null;
  }
};

const JobHistory = () => {
  const formatTimestamp = useFormatTimestamp();
  const [history, setHistory] = useState<JobHistoryItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [page, setPage] = useState(0);
  const limit = 25;

  const loadHistory = useCallback(async () => {
    setLoading(true);
    try {
      const response: JobHistoryResponse = await fetchAllJobHistory(limit, page * limit);
      setHistory(response.history);
      setTotal(response.total);
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'Failed to load job history');
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const filteredHistory = statusFilter === 'all'
    ? history
    : history.filter((h) => h.status === statusFilter);

  // Stats from current page data
  const completedCount = history.filter((h) => h.status === 'completed').length;
  const failedCount = history.filter((h) => h.status === 'failed').length;
  const cancelledCount = history.filter((h) => h.status === 'cancelled').length;

  return (
    <MainLayout>
        <Head>
          <title>Job History | Praxis</title>
        </Head>
        <PageHeader
          title="Job History"
          actions={
            <div className="flex items-center gap-3">
              <ExportButton endpoint="/api/backend/export/jobs" filename="jobs-export" />
              <Button
                variant="outline"
                size="sm"
                icon={<RefreshCw className="w-4 h-4" />}
                onClick={() => loadHistory()}
              >
                Refresh
              </Button>
              <HelpLink slug="jobs-and-scheduling" />
            </div>
          }
        />

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <StatCard label="Total Runs" value={total} />
          <StatCard label="Completed" value={completedCount} icon={<CheckCircle className="w-3 h-3 text-green-400" />} />
          <StatCard label="Failed" value={failedCount} icon={<XCircle className="w-3 h-3 text-red-400" />} />
          <StatCard label="Cancelled" value={cancelledCount} icon={<AlertTriangle className="w-3 h-3 text-content-muted" />} />
        </div>

        {/* Table */}
        <Card>
          <div className="p-6">
            {/* Filters */}
            <div className="flex items-center gap-4 mb-4">
              <Filter className="w-4 h-4 text-content-muted" />
              <div className="flex items-center gap-2">
                <label className="text-sm text-content-muted">Status:</label>
                <Select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                >
                  <option value="all">All</option>
                  <option value="completed">Completed</option>
                  <option value="failed">Failed</option>
                  <option value="running">Running</option>
                  <option value="cancelled">Cancelled</option>
                </Select>
              </div>
            </div>

            {/* Table Header */}
            <div className="grid grid-cols-8 gap-4 p-4 bg-surface-raised border-b border-border font-medium text-content text-sm rounded-t-lg">
              <div>Job Name</div>
              <div>Job Type</div>
              <div>Status</div>
              <div>Systems</div>
              <div>Started</div>
              <div>Duration</div>
              <div>Result</div>
              <div>Error</div>
            </div>

            {/* Loading */}
            {loading && <div className="p-4 text-content-muted">Loading...</div>}

            {/* Empty State */}
            {!loading && filteredHistory.length === 0 && (
              <EmptyState title="No job history found" />
            )}

            {/* Table Rows */}
            {!loading &&
              filteredHistory.map((item) => (
                <div key={item.id} className="grid grid-cols-8 gap-4 p-4 border-b border-border text-content hover:bg-white/[0.03]/50 text-sm items-center">
                  <div className="truncate font-medium" title={item.job_name}>{item.job_name}</div>
                  <div className="capitalize">{item.job_type ? humanizeLabel(item.job_type) : '-'}</div>
                  <div>
                    <Badge variant={statusToBadgeVariant(item.status)}>
                      <span className="inline-flex items-center gap-1">
                        {getStatusIcon(item.status)} {humanizeStatus(item.status)}
                      </span>
                    </Badge>
                  </div>
                  <div>
                    <span>{item.systems_completed}/{item.systems_targeted} completed</span>
                    {item.systems_failed > 0 && (
                      <span className="text-red-400 ml-1">({item.systems_failed} failed)</span>
                    )}
                  </div>
                  <div>{item.start_time ? formatTimestamp(item.start_time) : '-'}</div>
                  <div>{getDuration(item.start_time, item.end_time)}</div>
                  <div className="truncate" title={item.result ? summarizeJobResult(item.result) : undefined}>{summarizeJobResult(item.result)}</div>
                  <div className="truncate" title={item.error_message || undefined}>
                    {item.error_message ? (
                      <span className="text-red-400">{item.error_message}</span>
                    ) : '-'}
                  </div>
                </div>
              ))}

            {/* Pagination */}
            <div className="flex items-center justify-between p-4">
              <span className="text-sm text-content-muted">
                {total > 0
                  ? `Showing ${page * limit + 1}-${Math.min((page + 1) * limit, total)} of ${total}`
                  : 'No results'}
              </span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page === 0}
                  onClick={() => setPage((p) => p - 1)}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={(page + 1) * limit >= total}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </Button>
              </div>
            </div>
          </div>
        </Card>
    </MainLayout>
  );
};

export default JobHistory;
