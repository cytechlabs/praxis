import React, { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { PageHeader, Button, Card, CardBody, StatCard } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { RefreshCw, Server, Briefcase, Package, Layers, Bell } from 'lucide-react';
import { apiFetch } from '@/utils/api';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line, Legend, AreaChart, Area,
} from 'recharts';
import Head from 'next/head';

interface OverviewStats {
  total_systems: number;
  total_jobs_30d: number;
  total_packages: number;
  total_bulk_ops: number;
  active_alerts: number;
}

interface HealthTrends {
  current_snapshot: Record<string, number>;
  daily_changes: { date: string; changes: number }[];
  note: string | null;
}

interface ComplianceTrend {
  trend: { date: string; operations: Record<string, number> }[];
  note: string | null;
}

interface TopSystem {
  system_id: number;
  hostname: string;
  activity_count: number;
}

interface Failure {
  error: string;
  count: number;
}

const EmptyChart: React.FC<{ message?: string }> = ({ message = 'Not enough data to display chart' }) => (
  <div className="flex items-center justify-center h-64 text-gray-500 text-sm">
    {message}
  </div>
);

const AnalyticsDashboard: React.FC = () => {
  const [stats, setStats] = useState<OverviewStats | null>(null);
  const [health, setHealth] = useState<HealthTrends | null>(null);
  const [compliance, setCompliance] = useState<ComplianceTrend | null>(null);
  const [topSystems, setTopSystems] = useState<TopSystem[]>([]);
  const [failures, setFailures] = useState<Failure[]>([]);
  const [loading, setLoading] = useState(true);

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [statsRes, healthRes, compRes, topRes, failRes] = await Promise.all([
        apiFetch('/api/backend/analytics/overview-stats'),
        apiFetch('/api/backend/analytics/system-health-trends'),
        apiFetch('/api/backend/analytics/update-compliance-trend'),
        apiFetch('/api/backend/analytics/top-active-systems'),
        apiFetch('/api/backend/analytics/common-failures'),
      ]);
      if (statsRes.ok) setStats(await statsRes.json());
      if (healthRes.ok) setHealth(await healthRes.json());
      if (compRes.ok) setCompliance(await compRes.json());
      if (topRes.ok) {
        const d = await topRes.json();
        setTopSystems(d.systems || []);
      }
      if (failRes.ok) {
        const d = await failRes.json();
        setFailures(d.failures || []);
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load analytics');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  // Build health snapshot data for chart
  const snapshotData = health
    ? Object.entries(health.current_snapshot).map(([status, count]) => ({ status, count }))
    : [];

  // Build compliance trend data
  const complianceData = compliance?.trend?.map((t) => {
    const total = Object.values(t.operations).reduce((a, b) => a + b, 0);
    return { date: t.date, operations: total, ...t.operations };
  }) || [];

  return (
    <MainLayout>
        <Head>
          <title>Analytics Dashboard | Praxis</title>
        </Head>
        <PageHeader
          title="Analytics Dashboard"
          actions={
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={loadAll}
                icon={<RefreshCw className="w-4 h-4" />}
              >
                Refresh
              </Button>
              <HelpLink slug="monitoring-and-alerts" />
            </div>
          }
        />

        {loading && <div className="p-4 text-gray-400">Loading analytics...</div>}

        {!loading && (
          <>
            {/* Stats Row */}
            {stats && (
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                <StatCard label="Total Systems" value={stats.total_systems} icon={<Server className="w-5 h-5" />} />
                <StatCard label="Jobs (30d)" value={stats.total_jobs_30d} icon={<Briefcase className="w-5 h-5" />} />
                <StatCard label="Packages Managed" value={stats.total_packages} icon={<Package className="w-5 h-5" />} />
                <StatCard label="Bulk Ops (30d)" value={stats.total_bulk_ops} icon={<Layers className="w-5 h-5" />} />
                <StatCard label="Active Alerts" value={stats.active_alerts} icon={<Bell className="w-5 h-5" />} />
              </div>
            )}

            {/* Charts Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
              {/* System Health */}
              <Card>
                <CardBody>
                  <h2 className="text-lg font-semibold text-gray-200 mb-4">System Health Snapshot</h2>
                  {snapshotData.length === 0 ? (
                    <EmptyChart />
                  ) : (
                    <ResponsiveContainer width="100%" height={250}>
                      <BarChart data={snapshotData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                        <XAxis dataKey="status" tick={{ fill: '#9CA3AF', fontSize: 12 }} />
                        <YAxis tick={{ fill: '#9CA3AF', fontSize: 12 }} />
                        <Tooltip
                          contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', color: '#E5E7EB' }}
                        />
                        <Bar dataKey="count" fill="#EF4444" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  )}
                  {health?.daily_changes && health.daily_changes.length > 0 && (
                    <>
                      <h3 className="text-sm font-medium text-gray-400 mt-4 mb-2">Daily Status Changes (30d)</h3>
                      <ResponsiveContainer width="100%" height={150}>
                        <AreaChart data={health.daily_changes}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                          <XAxis dataKey="date" tick={{ fill: '#9CA3AF', fontSize: 10 }} />
                          <YAxis tick={{ fill: '#9CA3AF', fontSize: 10 }} />
                          <Tooltip
                            contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', color: '#E5E7EB' }}
                          />
                          <Area type="monotone" dataKey="changes" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.2} />
                        </AreaChart>
                      </ResponsiveContainer>
                    </>
                  )}
                  {health?.note && <p className="text-xs text-gray-500 mt-2">{health.note}</p>}
                </CardBody>
              </Card>

              {/* Compliance Trend */}
              <Card>
                <CardBody>
                  <h2 className="text-lg font-semibold text-gray-200 mb-4">Package Operations Trend</h2>
                  {complianceData.length === 0 ? (
                    <EmptyChart message={compliance?.note || 'Not enough data to display chart'} />
                  ) : (
                    <ResponsiveContainer width="100%" height={300}>
                      <LineChart data={complianceData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                        <XAxis dataKey="date" tick={{ fill: '#9CA3AF', fontSize: 10 }} />
                        <YAxis tick={{ fill: '#9CA3AF', fontSize: 12 }} />
                        <Tooltip
                          contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', color: '#E5E7EB' }}
                        />
                        <Legend />
                        <Line type="monotone" dataKey="operations" stroke="#10B981" strokeWidth={2} dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  )}
                </CardBody>
              </Card>

              {/* Top Active Systems */}
              <Card>
                <CardBody>
                  <h2 className="text-lg font-semibold text-gray-200 mb-4">Top Active Systems (30d)</h2>
                  {topSystems.length === 0 ? (
                    <EmptyChart />
                  ) : (
                    <ResponsiveContainer width="100%" height={300}>
                      <BarChart data={topSystems} layout="vertical">
                        <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                        <XAxis type="number" tick={{ fill: '#9CA3AF', fontSize: 12 }} />
                        <YAxis dataKey="hostname" type="category" width={120} tick={{ fill: '#9CA3AF', fontSize: 11 }} />
                        <Tooltip
                          contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', color: '#E5E7EB' }}
                        />
                        <Bar dataKey="activity_count" fill="#8B5CF6" radius={[0, 4, 4, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  )}
                </CardBody>
              </Card>

              {/* Common Failures */}
              <Card>
                <CardBody>
                  <h2 className="text-lg font-semibold text-gray-200 mb-4">Common Failures (30d)</h2>
                  {failures.length === 0 ? (
                    <EmptyChart message="No failures recorded in the last 30 days" />
                  ) : (
                    <div className="space-y-2">
                      {failures.map((f, idx) => (
                        <div key={idx} className="flex items-center gap-3">
                          <div className="flex-1 min-w-0">
                            <div className="w-full bg-gray-800 rounded-full h-6 overflow-hidden relative">
                              <div
                                className="h-full bg-red-700 rounded-full"
                                style={{ width: `${Math.min(100, (f.count / (failures[0]?.count || 1)) * 100)}%` }}
                              />
                              <span className="absolute inset-0 flex items-center px-2 text-xs text-gray-200 truncate">
                                {f.error.length > 80 ? f.error.slice(0, 80) + '...' : f.error}
                              </span>
                            </div>
                          </div>
                          <span className="text-sm font-medium text-red-400 w-10 text-right">{f.count}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </CardBody>
              </Card>
            </div>
          </>
        )}
    </MainLayout>
  );
};

export default AnalyticsDashboard;
