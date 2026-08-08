import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import { AlertTriangle, CheckCircle2, Activity, Clock } from 'lucide-react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import MainLayout from '@/components/MainLayout';
import { useAuth } from '@/context/AuthContext';
import { useRouter } from 'next/router';
import {
  getMetricsReport,
  getErrorPatterns,
  getPerformanceTrends,
  MetricsReportResponse,
  ErrorPatternsResponse,
  PerformanceTrendsResponse,
} from '@/services/commandExecutionService';
import Head from 'next/head';
import { PageHeader, Card, CardHeader, CardBody, StatCard, SkeletonCards } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';

const getNum = (obj: Record<string, unknown> | undefined, key: string, fallback = 0): number => {
  if (!obj) return fallback;
  const v = obj[key];
  return typeof v === 'number' ? v : fallback;
};

const CommandMetricsPage: React.FC = () => {
  const router = useRouter();
  const { user, loading: authLoading } = useAuth();

  const [days, setDays] = useState<number>(7);
  const [metrics, setMetrics] = useState<MetricsReportResponse | null>(null);
  const [errorPatterns, setErrorPatterns] = useState<ErrorPatternsResponse | null>(null);
  const [trends, setTrends] = useState<PerformanceTrendsResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (authLoading) return;
    if (!user) router.push('/login');
  }, [authLoading, user, router]);

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      // performance/trends requires days >= 7
      const trendsDays = Math.max(days, 7);
      const [m, ep, tr] = await Promise.all([
        getMetricsReport(days),
        getErrorPatterns(days),
        getPerformanceTrends(trendsDays),
      ]);
      setMetrics(m);
      setErrorPatterns(ep);
      setTrends(tr);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load metrics');
    } finally {
      setLoading(false);
    }
  }, [days]);

  useEffect(() => {
    if (authLoading || !user) return;
    loadAll();
  }, [authLoading, user, loadAll]);

  const summary = (metrics?.summary as Record<string, unknown>) || {};
  const performance = (metrics?.performance as Record<string, unknown>) || {};

  const totalExecutions = getNum(summary, 'total_executions');
  const successful = getNum(summary, 'successful_executions');
  const failed = getNum(summary, 'failed_executions');
  const validationFailures = getNum(summary, 'validation_failures');
  const highRisk = getNum(summary, 'high_risk_executions');
  const successRate =
    totalExecutions > 0 ? ((successful / totalExecutions) * 100).toFixed(1) : '0.0';
  const avgTime = getNum(performance, 'avg_execution_time_ms');

  // Merge trend lines into a single dataset for recharts
  const chartData = useMemo(() => {
    if (!trends) return [];
    const countMap = new Map<string, number>();
    const successMap = new Map<string, number>();
    trends.trends.execution_count_trend.forEach((p) => countMap.set(p.date, p.value));
    trends.trends.success_rate_trend.forEach((p) => successMap.set(p.date, p.value));
    const dates = Array.from(new Set([...countMap.keys(), ...successMap.keys()])).sort();
    return dates.map((date) => ({
      date,
      executions: countMap.get(date) ?? 0,
      success_rate: Number((successMap.get(date) ?? 0).toFixed(1)),
    }));
  }, [trends]);

  const errorRows = useMemo(() => {
    if (!errorPatterns) return [];
    return Object.entries(errorPatterns.error_patterns)
      .map(([category, data]) => ({ category, ...data }))
      .sort((a, b) => b.count - a.count);
  }, [errorPatterns]);

  return (
    <MainLayout>
        <Head>
          <title>Command Metrics | Praxis</title>
        </Head>
      <div className="space-y-6">
        <PageHeader
          title="Command Metrics"
          actions={
            <div className="flex items-center gap-2">
              <label className="text-sm text-content-muted">Range:</label>
              <select
                value={days}
                onChange={(e) => setDays(parseInt(e.target.value, 10))}
                className="bg-white/[0.02] border border-border-strong text-content rounded px-2 py-1 text-sm"
              >
                <option value={7}>7 days</option>
                <option value={14}>14 days</option>
                <option value={30}>30 days</option>
              </select>
              <HelpLink slug="ssh-and-security" />
            </div>
          }
        />

        {loading ? (
          <SkeletonCards count={5} />
        ) : (
          <>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
              <StatCard label="Total Executions" value={totalExecutions} icon={<Activity size={16} />} />
              <StatCard label="Success Rate" value={`${successRate}%`} icon={<CheckCircle2 size={16} />} />
              <StatCard label="Avg Time (ms)" value={avgTime} icon={<Clock size={16} />} />
              <StatCard
                label="Validation Failures"
                value={validationFailures}
                icon={<AlertTriangle size={16} />}
              />
              <StatCard label="High Risk" value={highRisk} icon={<AlertTriangle size={16} />} />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm">
              <Card>
                <CardBody>
                  <div className="text-content-muted text-xs uppercase">Successful</div>
                  <div className="text-content text-lg">{successful}</div>
                </CardBody>
              </Card>
              <Card>
                <CardBody>
                  <div className="text-content-muted text-xs uppercase">Failed</div>
                  <div className="text-content text-lg">{failed}</div>
                </CardBody>
              </Card>
              <Card>
                <CardBody>
                  <div className="text-content-muted text-xs uppercase">Error Rate</div>
                  <div className="text-content text-lg">
                    {errorPatterns ? `${errorPatterns.error_rate.toFixed(1)}%` : '-'}
                  </div>
                </CardBody>
              </Card>
              <Card>
                <CardBody>
                  <div className="text-content-muted text-xs uppercase">Total Errors</div>
                  <div className="text-content text-lg">
                    {errorPatterns ? errorPatterns.total_errors : '-'}
                  </div>
                </CardBody>
              </Card>
            </div>

            {/* Performance trends */}
            <Card>
              <CardHeader>Performance Trends</CardHeader>
              <CardBody>
                {chartData.length === 0 ? (
                  <div className="text-content-subtle text-sm h-64 flex items-center justify-center">
                    Not enough data to display chart
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height={280}>
                    <LineChart data={chartData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#3f3f46" />
                      <XAxis dataKey="date" stroke="#9ca3af" fontSize={12} />
                      <YAxis yAxisId="left" stroke="#9ca3af" fontSize={12} />
                      <YAxis
                        yAxisId="right"
                        orientation="right"
                        stroke="#9ca3af"
                        fontSize={12}
                        domain={[0, 100]}
                      />
                      <Tooltip
                        contentStyle={{ backgroundColor: '#030712', border: '1px solid #1f2937' }}
                        labelStyle={{ color: '#e5e7eb' }}
                      />
                      <Legend />
                      <Line
                        yAxisId="left"
                        type="monotone"
                        dataKey="executions"
                        stroke="#ef4444"
                        name="Executions"
                        strokeWidth={2}
                        dot={false}
                      />
                      <Line
                        yAxisId="right"
                        type="monotone"
                        dataKey="success_rate"
                        stroke="#10b981"
                        name="Success Rate %"
                        strokeWidth={2}
                        dot={false}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                )}
              </CardBody>
            </Card>

            {/* Error patterns */}
            <Card>
              <CardHeader>Common Error Patterns</CardHeader>
              <CardBody>
                {errorRows.length === 0 ? (
                  <div className="text-content-subtle text-sm">No error patterns detected.</div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead className="text-content-muted uppercase text-xs">
                        <tr>
                          <th scope="col" className="text-left py-1">Category</th>
                          <th scope="col" className="text-right py-1">Count</th>
                          <th scope="col" className="text-right py-1">Percentage</th>
                          <th scope="col" className="text-left py-1">Suggested Fixes</th>
                        </tr>
                      </thead>
                      <tbody className="text-content">
                        {errorRows.map((r) => (
                          <tr key={r.category} className="border-t border-border">
                            <td className="py-1 font-mono text-xs">{r.category}</td>
                            <td className="py-1 text-right">{r.count}</td>
                            <td className="py-1 text-right">{r.percentage.toFixed(1)}%</td>
                            <td className="py-1 text-xs">
                              {r.suggested_fixes.length > 0
                                ? r.suggested_fixes.join('; ')
                                : '-'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </CardBody>
            </Card>
          </>
        )}
      </div>
    </MainLayout>
  );
};

export default CommandMetricsPage;
