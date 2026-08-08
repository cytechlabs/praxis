import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useRouter } from 'next/router';
import { toast } from 'sonner';
import {
  Play,
  Loader2,
  ChevronDown,
  ChevronRight,
  XCircle,
  Activity,
  History as HistoryIcon,
  Sparkles,
} from 'lucide-react';
import MainLayout from '@/components/MainLayout';
import { useAuth } from '@/context/AuthContext';
import { fetchAllSystems, SystemListItem } from '@/services/systemService';
import {
  executeCommandRich,
  getExecutionResult,
  getActiveExecutions,
  killExecution,
  getExecutionHistory,
  processExecutionResult,
  CommandExecutionResponse,
  ActiveExecutionResponse,
  ResultProcessingResponse,
} from '@/services/commandExecutionService';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { PageHeader, Button, Card, CardBody, ConfirmModal } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';

const statusBadgeClass = (statusRaw: string | null | undefined): string => {
  const status = (statusRaw || '').toLowerCase();
  if (['completed', 'success', 'succeeded'].includes(status)) {
    return 'bg-green-900 text-green-200 border-green-700';
  }
  if (['failed', 'error', 'timeout', 'killed'].includes(status)) {
    return 'bg-red-900 text-red-200 border-red-700';
  }
  if (['running', 'pending', 'queued'].includes(status)) {
    return 'bg-yellow-900 text-yellow-200 border-yellow-700';
  }
  return 'bg-gray-800 text-gray-300 border-gray-600';
};

const validationBadgeClass = (statusRaw: string | null | undefined): string => {
  const status = (statusRaw || '').toLowerCase();
  if (['passed', 'valid', 'allowed'].includes(status)) {
    return 'bg-green-900 text-green-200 border-green-700';
  }
  if (['failed', 'rejected', 'blocked'].includes(status)) {
    return 'bg-red-900 text-red-200 border-red-700';
  }
  if (['bypassed', 'skipped'].includes(status)) {
    return 'bg-orange-900 text-orange-200 border-orange-700';
  }
  return 'bg-surface-overlay text-content border-border-strong';
};

const riskBadgeClass = (riskRaw: string | null | undefined): string => {
  const risk = (riskRaw || '').toLowerCase();
  if (risk === 'low') return 'bg-green-900 text-green-200 border-green-700';
  if (risk === 'medium') return 'bg-yellow-900 text-yellow-200 border-yellow-700';
  if (risk === 'high') return 'bg-orange-900 text-orange-200 border-orange-700';
  if (risk === 'critical') return 'bg-red-900 text-red-200 border-red-700';
  return 'bg-gray-800 text-gray-300 border-gray-600';
};

const InlineBadge: React.FC<{ label: string; className: string }> = ({ label, className }) => (
  <span className={`inline-block px-2 py-0.5 text-xs rounded border ${className}`}>
    {label}
  </span>
);

const CommandExecutionPage: React.FC = () => {
  const router = useRouter();
  const { user, loading: authLoading, isAdmin, canWrite } = useAuth();
  // PRA-258: subscribe to timestamp preferences (local formatDateTime closure).
  const formatTimestamp = useFormatTimestamp();
  const formatDateTime = (iso: string | null | undefined): string => {
    if (!iso) return '-';
    try {
      return formatTimestamp(iso);
    } catch {
      return iso;
    }
  };

  const [systems, setSystems] = useState<SystemListItem[]>([]);
  const [selectedSystemId, setSelectedSystemId] = useState<number | null>(null);
  const [command, setCommand] = useState('');
  const [timeoutSeconds, setTimeoutSeconds] = useState<string>('');
  const [bypassValidation, setBypassValidation] = useState(false);

  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<CommandExecutionResponse | null>(null);
  const [analysis, setAnalysis] = useState<ResultProcessingResponse | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisOpen, setAnalysisOpen] = useState(false);

  const [activeExecutions, setActiveExecutions] = useState<ActiveExecutionResponse[]>([]);
  const [activeOpen, setActiveOpen] = useState(true);

  const [history, setHistory] = useState<CommandExecutionResponse[]>([]);
  const [historyLimit] = useState(25);
  const [historyOffset, setHistoryOffset] = useState(0);
  const [historyLoading, setHistoryLoading] = useState(false);

  const pollingRef = useRef<number | null>(null);

  // Kill confirm state
  const [showKillConfirm, setShowKillConfirm] = useState(false);
  const [killTargetId, setKillTargetId] = useState<number | null>(null);

  // Load systems once
  useEffect(() => {
    if (authLoading) return;
    if (!user) {
      router.push('/login');
      return;
    }
    (async () => {
      try {
        const list = await fetchAllSystems();
        setSystems(list);
      } catch (err) {
        toast.error(err instanceof Error ? err.message : 'Failed to load systems');
      }
    })();
  }, [authLoading, user, router]);

  // Honor ?system_id=&view= query params
  useEffect(() => {
    if (!router.isReady) return;
    const sid = router.query.system_id;
    if (typeof sid === 'string' && sid.length > 0) {
      const parsed = parseInt(sid, 10);
      if (!Number.isNaN(parsed)) setSelectedSystemId(parsed);
    }
    const view = router.query.view;
    if (typeof view === 'string' && view.length > 0) {
      const parsed = parseInt(view, 10);
      if (!Number.isNaN(parsed)) {
        (async () => {
          try {
            const r = await getExecutionResult(parsed);
            setResult(r);
            if (r.system_id) setSelectedSystemId(r.system_id);
            setCommand(r.command || '');
            // auto-load analysis
            try {
              const a = await processExecutionResult(parsed);
              setAnalysis(a);
              setAnalysisOpen(true);
            } catch {
              // ignore analysis errors
            }
          } catch (err) {
            toast.error(err instanceof Error ? err.message : 'Failed to load execution');
          }
        })();
      }
    }
  }, [router.isReady, router.query]);

  // Active executions polling
  const fetchActive = useCallback(async () => {
    try {
      const list = await getActiveExecutions();
      setActiveExecutions(list);
    } catch {
      // silent
    }
  }, []);

  useEffect(() => {
    fetchActive();
    const id = window.setInterval(fetchActive, 5000);
    return () => window.clearInterval(id);
  }, [fetchActive]);

  // History
  const fetchHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const list = await getExecutionHistory(undefined, historyLimit, historyOffset);
      setHistory(list);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to fetch history');
    } finally {
      setHistoryLoading(false);
    }
  }, [historyLimit, historyOffset]);

  useEffect(() => {
    if (authLoading || !user) return;
    fetchHistory();
  }, [authLoading, user, fetchHistory]);

  // Poll a running execution to completion
  useEffect(() => {
    if (!result) return;
    const status = (result.execution_status || '').toLowerCase();
    if (!['running', 'pending', 'queued'].includes(status)) return;

    const executionId = result.id;
    pollingRef.current = window.setInterval(async () => {
      try {
        const latest = await getExecutionResult(executionId);
        setResult(latest);
        const s = (latest.execution_status || '').toLowerCase();
        if (!['running', 'pending', 'queued'].includes(s)) {
          if (pollingRef.current) {
            window.clearInterval(pollingRef.current);
            pollingRef.current = null;
          }
        }
      } catch {
        // silent
      }
    }, 2000);

    return () => {
      if (pollingRef.current) {
        window.clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
    };
  }, [result]);

  const handleExecute = useCallback(async () => {
    if (!selectedSystemId) {
      toast.error('Select a system first');
      return;
    }
    if (!command.trim()) {
      toast.error('Enter a command');
      return;
    }
    setSubmitting(true);
    setAnalysis(null);
    setAnalysisOpen(false);
    try {
      const payload = {
        system_id: selectedSystemId,
        command,
        timeout_seconds: timeoutSeconds ? parseInt(timeoutSeconds, 10) : undefined,
        bypass_validation: isAdmin ? bypassValidation : false,
      };
      const r = await executeCommandRich(payload);
      setResult(r);
      if ((r.validation_status || '').toLowerCase() === 'failed') {
        toast.error('Command validation failed');
      } else {
        toast.success('Command submitted');
      }
      // Refresh history so the new row appears
      fetchHistory();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Execution failed');
    } finally {
      setSubmitting(false);
    }
  }, [selectedSystemId, command, timeoutSeconds, bypassValidation, isAdmin, fetchHistory]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if (e.ctrlKey && e.key === 'Enter') {
        e.preventDefault();
        handleExecute();
      }
    },
    [handleExecute]
  );

  const handleAnalyze = useCallback(async () => {
    if (!result) return;
    setAnalyzing(true);
    try {
      const a = await processExecutionResult(result.id);
      setAnalysis(a);
      setAnalysisOpen(true);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setAnalyzing(false);
    }
  }, [result]);

  const handleKill = useCallback(
    async (execId: number) => {
      try {
        await killExecution(execId);
        toast.success('Kill requested');
        fetchActive();
      } catch (err) {
        toast.error(err instanceof Error ? err.message : 'Kill failed');
      }
      setShowKillConfirm(false);
      setKillTargetId(null);
    },
    [fetchActive]
  );

  const loadHistoryItem = useCallback(async (execId: number) => {
    try {
      const r = await getExecutionResult(execId);
      setResult(r);
      setAnalysis(null);
      setAnalysisOpen(false);
      try {
        const a = await processExecutionResult(execId);
        setAnalysis(a);
        setAnalysisOpen(true);
      } catch {
        // ignore
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load execution');
    }
  }, []);

  const systemHostnameMap = useMemo(() => {
    const m = new Map<number, string>();
    systems.forEach((s) => m.set(s.id, s.hostname));
    return m;
  }, [systems]);

  if (authLoading) {
    return (
      <MainLayout>
        <Head>
          <title>Command Execution | Praxis</title>
        </Head>
        <div className="text-content-muted">Loading...</div>
      </MainLayout>
    );
  }

  if (!canWrite) {
    return (
      <MainLayout>
        <div className="bg-red-900/40 border border-red-700 text-red-200 rounded p-4">
          Access denied. You need admin or maintainer role to execute commands.
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Head>
        <title>Command Execution | Praxis</title>
      </Head>
      <div className="space-y-6">
        <PageHeader title="Command Execution" actions={<HelpLink slug="ssh-and-security" />} />

        {/* Execution form */}
        <Card>
          <CardBody className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="md:col-span-2">
                <label className="block text-xs text-content-muted uppercase tracking-wide mb-1">
                  Target System
                </label>
                <select
                  value={selectedSystemId ?? ''}
                  onChange={(e) =>
                    setSelectedSystemId(e.target.value ? parseInt(e.target.value, 10) : null)
                  }
                  className="w-full bg-white/[0.02] border border-border-strong text-content rounded px-3 py-2"
                >
                  <option value="">-- select a system --</option>
                  {systems.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.hostname} ({s.ip_address})
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs text-content-muted uppercase tracking-wide mb-1">
                  Timeout (seconds, optional)
                </label>
                <input
                  type="number"
                  min={1}
                  value={timeoutSeconds}
                  onChange={(e) => setTimeoutSeconds(e.target.value)}
                  placeholder="default"
                  className="w-full bg-white/[0.02] border border-border-strong text-content rounded px-3 py-2"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs text-content-muted uppercase tracking-wide mb-1">
                Command (Ctrl+Enter to execute)
              </label>
              <textarea
                value={command}
                onChange={(e) => setCommand(e.target.value)}
                onKeyDown={handleKeyDown}
                rows={4}
                spellCheck={false}
                className="w-full bg-white/[0.02] border border-border-strong text-content rounded px-3 py-2 font-mono text-sm"
                placeholder="uname -a"
              />
            </div>

            <div className="flex items-center justify-between flex-wrap gap-3">
              {isAdmin ? (
                <label className="flex items-center gap-2 text-sm text-content">
                  <input
                    type="checkbox"
                    checked={bypassValidation}
                    onChange={(e) => setBypassValidation(e.target.checked)}
                    className="accent-red-600"
                  />
                  Bypass validation (admin only)
                </label>
              ) : (
                <div />
              )}
              <Button
                variant="primary"
                icon={submitting ? <Loader2 className="animate-spin" size={16} /> : <Play size={16} />}
                onClick={handleExecute}
                disabled={submitting || !selectedSystemId || !command.trim()}
              >
                Execute
              </Button>
            </div>
          </CardBody>
        </Card>

        {/* Result panel */}
        {result && (
          <Card>
            <CardBody className="space-y-4">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <InlineBadge
                    label={result.execution_status || 'unknown'}
                    className={statusBadgeClass(result.execution_status)}
                  />
                  <InlineBadge
                    label={`validation: ${result.validation_status || 'unknown'}`}
                    className={validationBadgeClass(result.validation_status)}
                  />
                  <InlineBadge
                    label={`risk: ${result.risk_level || 'unknown'}`}
                    className={riskBadgeClass(result.risk_level)}
                  />
                  <span className="text-xs text-content-muted">
                    exit code: {result.exit_code ?? '-'}
                  </span>
                  <span className="text-xs text-content-muted">
                    time: {result.execution_time_ms ?? '-'} ms
                  </span>
                  {result.requires_sudo && (
                    <InlineBadge label="sudo" className="bg-orange-900 text-orange-200 border-orange-700" />
                  )}
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  icon={analyzing ? <Loader2 className="animate-spin" size={14} /> : <Sparkles size={14} />}
                  onClick={handleAnalyze}
                  disabled={analyzing}
                >
                  Analyze
                </Button>
              </div>

              {(result.validation_status || '').toLowerCase() === 'failed' && result.error_message && (
                <div className="bg-red-900/40 border border-red-700 text-red-200 rounded p-3 text-sm">
                  <span className="font-semibold">Validation failed: </span>
                  {result.error_message}
                </div>
              )}

              <div>
                <div className="text-xs text-content-muted uppercase mb-1">Command</div>
                <pre className="bg-surface-sunken border border-border rounded p-2 font-mono text-sm text-content whitespace-pre-wrap">
                  {result.command}
                </pre>
              </div>

              <div>
                <div className="text-xs text-content-muted uppercase mb-1">stdout</div>
                <pre className="bg-surface-sunken border border-border rounded p-2 font-mono text-xs text-content max-h-64 overflow-auto whitespace-pre-wrap">
                  {result.stdout || <span className="text-content-subtle">(empty)</span>}
                </pre>
              </div>

              <div>
                <div className="text-xs text-content-muted uppercase mb-1">stderr</div>
                <pre className="bg-surface-sunken border border-border rounded p-2 font-mono text-xs text-red-300 max-h-64 overflow-auto whitespace-pre-wrap">
                  {result.stderr || <span className="text-content-subtle">(empty)</span>}
                </pre>
              </div>

              <div className="text-xs text-content-subtle">
                started: {formatDateTime(result.started_at)} &middot; completed:{' '}
                {formatDateTime(result.completed_at)}
              </div>

              {analysis && (
                <div className="border border-border-strong rounded">
                  <button
                    onClick={() => setAnalysisOpen((v) => !v)}
                    className="w-full flex items-center justify-between px-3 py-2 text-sm text-content hover:bg-surface-overlay"
                  >
                    <span className="flex items-center gap-2">
                      <Sparkles size={14} />
                      Analysis
                    </span>
                    {analysisOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  </button>
                  {analysisOpen && (
                    <div className="px-3 py-2 space-y-3 text-xs">
                      <div>
                        <div className="text-content-muted uppercase mb-1">Parsed output</div>
                        <pre className="bg-surface-sunken border border-border rounded p-2 text-content max-h-48 overflow-auto">
                          {JSON.stringify(analysis.parsed_output, null, 2)}
                        </pre>
                      </div>
                      <div>
                        <div className="text-content-muted uppercase mb-1">Error analysis</div>
                        <pre className="bg-surface-sunken border border-border rounded p-2 text-content max-h-48 overflow-auto">
                          {JSON.stringify(analysis.error_analysis, null, 2)}
                        </pre>
                      </div>
                      <div>
                        <div className="text-content-muted uppercase mb-1">Formatted result</div>
                        <pre className="bg-surface-sunken border border-border rounded p-2 text-content max-h-48 overflow-auto">
                          {JSON.stringify(analysis.formatted_result, null, 2)}
                        </pre>
                      </div>
                      <div>
                        <div className="text-content-muted uppercase mb-1">Status info</div>
                        <pre className="bg-surface-sunken border border-border rounded p-2 text-content max-h-48 overflow-auto">
                          {JSON.stringify(analysis.status_info, null, 2)}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </CardBody>
          </Card>
        )}

        {/* Active executions */}
        <Card>
          <div>
            <button
              onClick={() => setActiveOpen((v) => !v)}
              className="w-full flex items-center justify-between px-4 py-3 text-content hover:bg-surface-overlay/50"
            >
              <span className="flex items-center gap-2">
                <Activity size={16} className="text-red-400" />
                <span className="font-semibold">Active executions</span>
                <span className="text-xs text-content-subtle">({activeExecutions.length})</span>
              </span>
              {activeOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
            </button>
            {activeOpen && (
              <div className="px-4 pb-3">
                {activeExecutions.length === 0 ? (
                  <div className="text-sm text-content-subtle py-2">None running.</div>
                ) : (
                  <table className="w-full text-sm">
                    <thead className="text-content-muted uppercase text-xs">
                      <tr>
                        <th scope="col" className="text-left py-1">ID</th>
                        <th scope="col" className="text-left py-1">System</th>
                        <th scope="col" className="text-left py-1">Command</th>
                        <th scope="col" className="text-right py-1">Elapsed</th>
                        <th scope="col" className="text-right py-1">Timeout</th>
                        <th scope="col" className="text-right py-1"></th>
                      </tr>
                    </thead>
                    <tbody className="text-content">
                      {activeExecutions.map((e) => (
                        <tr key={e.execution_id} className="border-t border-border">
                          <td className="py-1">{e.execution_id}</td>
                          <td className="py-1">{e.system_hostname}</td>
                          <td className="py-1 font-mono text-xs truncate max-w-xs">{e.command}</td>
                          <td className="py-1 text-right">{e.elapsed_time.toFixed(1)}s</td>
                          <td className="py-1 text-right">{e.timeout}s</td>
                          <td className="py-1 text-right">
                            <button
                              onClick={() => {
                                setKillTargetId(e.execution_id);
                                setShowKillConfirm(true);
                              }}
                              className="inline-flex items-center gap-1 px-2 py-0.5 text-xs text-red-300 hover:text-red-100"
                            >
                              <XCircle size={12} /> Kill
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}
          </div>
        </Card>

        {/* Recent history */}
        <Card>
          <CardBody>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2 text-content">
                <HistoryIcon size={16} className="text-red-400" />
                <span className="font-semibold">Recent history</span>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setHistoryOffset(Math.max(0, historyOffset - historyLimit))}
                  disabled={historyOffset === 0}
                >
                  Prev
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setHistoryOffset(historyOffset + historyLimit)}
                  disabled={history.length < historyLimit}
                >
                  Next
                </Button>
              </div>
            </div>
            {historyLoading ? (
              <div className="text-sm text-content-subtle">Loading...</div>
            ) : history.length === 0 ? (
              <div className="text-sm text-content-subtle">No history yet.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="text-content-muted uppercase text-xs">
                    <tr>
                      <th scope="col" className="text-left py-1">Time</th>
                      <th scope="col" className="text-left py-1">System</th>
                      <th scope="col" className="text-left py-1">Command</th>
                      <th scope="col" className="text-left py-1">Status</th>
                      <th scope="col" className="text-right py-1">Exit</th>
                      <th scope="col" className="text-right py-1">Time (ms)</th>
                      <th scope="col" className="text-left py-1">Risk</th>
                    </tr>
                  </thead>
                  <tbody className="text-content">
                    {history.map((h) => (
                      <tr
                        key={h.id}
                        onClick={() => loadHistoryItem(h.id)}
                        className="border-t border-border hover:bg-surface-overlay cursor-pointer"
                      >
                        <td className="py-1 text-xs">{formatDateTime(h.started_at)}</td>
                        <td className="py-1 text-xs">
                          {h.system_hostname || systemHostnameMap.get(h.system_id) || `#${h.system_id}`}
                        </td>
                        <td className="py-1 font-mono text-xs truncate max-w-xs">{h.command}</td>
                        <td className="py-1">
                          <InlineBadge
                            label={h.execution_status || '-'}
                            className={statusBadgeClass(h.execution_status)}
                          />
                        </td>
                        <td className="py-1 text-right">{h.exit_code ?? '-'}</td>
                        <td className="py-1 text-right">{h.execution_time_ms ?? '-'}</td>
                        <td className="py-1">
                          <InlineBadge
                            label={h.risk_level || '-'}
                            className={riskBadgeClass(h.risk_level)}
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardBody>
        </Card>

        <ConfirmModal
          open={showKillConfirm}
          onClose={() => { setShowKillConfirm(false); setKillTargetId(null); }}
          onConfirm={() => killTargetId && handleKill(killTargetId)}
          title="Kill Execution"
          message={`Kill execution ${killTargetId}?`}
          confirmLabel="Kill"
          variant="danger"
        />
      </div>
    </MainLayout>
  );
};

export default CommandExecutionPage;
