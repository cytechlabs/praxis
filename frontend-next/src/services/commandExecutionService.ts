import { apiFetch, formatApiError } from '../utils/api';

// ===== Command Execution Types =====

export interface CommandExecutionRequest {
  system_id: number;
  command: string;
  timeout_seconds?: number;
  session_id?: string;
  bypass_validation?: boolean;
  execution_context?: Record<string, unknown>;
}

export interface CommandExecutionResponse {
  id: number;
  system_id: number;
  system_hostname: string | null;
  user_id: number;
  username: string | null;
  session_id: string | null;
  command: string;
  normalized_command: string;
  command_hash: string;
  execution_status: string;
  exit_code: number | null;
  stdout: string | null;
  stderr: string | null;
  started_at: string | null;
  completed_at: string | null;
  execution_time_ms: number | null;
  timeout_seconds: number;
  max_memory_usage_bytes: number | null;
  cpu_time_ms: number | null;
  validation_status: string;
  risk_level: string;
  requires_sudo: boolean;
  actual_user: string | null;
  error_type: string | null;
  error_message: string | null;
  retry_count: number;
  execution_context: Record<string, unknown> | null;
}

export interface ActiveExecutionResponse {
  execution_id: number;
  system_hostname: string;
  command: string;
  start_time: number;
  timeout: number;
  elapsed_time: number;
}

export interface ExecutionTestResponse {
  system_id: number;
  test_status: string;
  execution_time_ms?: number | null;
  stdout?: string | null;
  stderr?: string | null;
  error_message?: string | null;
  tested_at: string;
}

// ===== Result Processing Types =====

export interface ResultProcessingResponse {
  execution_id: number;
  processed_at: string;
  parsed_output: Record<string, unknown>;
  error_analysis: Record<string, unknown>;
  formatted_result: Record<string, unknown>;
  status_info: Record<string, unknown>;
  processing_status: string;
  error_message?: string | null;
}

export interface ExecutionHistoryWithAnalysisResponse {
  total_count: number;
  limit: number;
  offset: number;
  executions: Array<Record<string, unknown>>;
}

export interface MetricsReportResponse {
  period: Record<string, unknown>;
  summary: Record<string, unknown>;
  performance: Record<string, unknown>;
  daily_breakdown: Array<Record<string, unknown>>;
}

export interface PerformanceTrendsResponse {
  analysis_period_days: number;
  system_id: number | null;
  summary: Record<string, unknown>;
  performance: Record<string, unknown>;
  trends: {
    execution_count_trend: Array<{ date: string; value: number }>;
    success_rate_trend: Array<{ date: string; value: number }>;
    avg_execution_time_trend: Array<{ date: string; value: number }>;
  };
  generated_at: string;
}

export interface ErrorPatternsResponse {
  analysis_period_days: number;
  total_executions_analyzed: number;
  total_errors: number;
  error_rate: number;
  error_patterns: Record<
    string,
    {
      count: number;
      percentage: number;
      recent_examples: Array<{
        execution_id: number;
        command: string;
        error_messages: string[];
      }>;
      suggested_fixes: string[];
    }
  >;
  generated_at: string;
}

// ===== Helpers =====

async function parseOrThrow<T>(response: Response, fallback: string): Promise<T> {
  if (!response.ok) {
    let detail = fallback;
    try {
      const data = await response.json();
      detail = formatApiError(data, fallback);
    } catch {
      // ignore
    }
    throw new Error(detail);
  }
  return response.json() as Promise<T>;
}

// ===== Command Execution API =====

export const executeCommandRich = async (
  request: CommandExecutionRequest
): Promise<CommandExecutionResponse> => {
  const response = await apiFetch('/api/backend/command-execution/execute', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
  return parseOrThrow<CommandExecutionResponse>(response, 'Failed to execute command');
};

export const getExecutionHistory = async (
  systemId?: number,
  limit = 100,
  offset = 0
): Promise<CommandExecutionResponse[]> => {
  const params = new URLSearchParams();
  if (systemId !== undefined) params.append('system_id', String(systemId));
  params.append('limit', String(limit));
  params.append('offset', String(offset));
  const response = await apiFetch(
    `/api/backend/command-execution/history?${params.toString()}`
  );
  return parseOrThrow<CommandExecutionResponse[]>(response, 'Failed to fetch history');
};

export const getActiveExecutions = async (): Promise<ActiveExecutionResponse[]> => {
  const response = await apiFetch('/api/backend/command-execution/active');
  return parseOrThrow<ActiveExecutionResponse[]>(
    response,
    'Failed to fetch active executions'
  );
};

export const killExecution = async (
  executionId: number
): Promise<{ message: string }> => {
  const response = await apiFetch(
    `/api/backend/command-execution/active/${executionId}`,
    { method: 'DELETE' }
  );
  return parseOrThrow<{ message: string }>(response, 'Failed to kill execution');
};

export const testCommandExecution = async (
  systemId: number
): Promise<ExecutionTestResponse> => {
  const response = await apiFetch(
    `/api/backend/command-execution/test/${systemId}`,
    { method: 'POST' }
  );
  return parseOrThrow<ExecutionTestResponse>(response, 'Failed to test execution');
};

export const getExecutionResult = async (
  executionId: number
): Promise<CommandExecutionResponse> => {
  const response = await apiFetch(
    `/api/backend/command-execution/result/${executionId}`
  );
  return parseOrThrow<CommandExecutionResponse>(response, 'Failed to fetch result');
};

// ===== Command Result Processing API =====

export const processExecutionResult = async (
  executionId: number
): Promise<ResultProcessingResponse> => {
  const response = await apiFetch(
    `/api/backend/command-results/process/${executionId}`,
    { method: 'POST' }
  );
  return parseOrThrow<ResultProcessingResponse>(response, 'Failed to process result');
};

export const getHistoryWithAnalysis = async (
  systemId?: number,
  limit = 50,
  offset = 0,
  includeAnalysis = true
): Promise<ExecutionHistoryWithAnalysisResponse> => {
  const params = new URLSearchParams();
  if (systemId !== undefined) params.append('system_id', String(systemId));
  params.append('limit', String(limit));
  params.append('offset', String(offset));
  params.append('include_analysis', String(includeAnalysis));
  const response = await apiFetch(
    `/api/backend/command-results/history?${params.toString()}`
  );
  return parseOrThrow<ExecutionHistoryWithAnalysisResponse>(
    response,
    'Failed to fetch history'
  );
};

export const getMetricsReport = async (
  days = 7,
  systemId?: number
): Promise<MetricsReportResponse> => {
  const params = new URLSearchParams();
  params.append('days', String(days));
  if (systemId !== undefined) params.append('system_id', String(systemId));
  const response = await apiFetch(
    `/api/backend/command-results/metrics/report?${params.toString()}`
  );
  return parseOrThrow<MetricsReportResponse>(response, 'Failed to fetch metrics');
};

export const getExecutionAnalysis = async (
  executionId: number
): Promise<ResultProcessingResponse> => {
  const response = await apiFetch(
    `/api/backend/command-results/analysis/${executionId}`
  );
  return parseOrThrow<ResultProcessingResponse>(response, 'Failed to fetch analysis');
};

export const getSystemExecutionSummary = async (
  systemId: number,
  days = 7
): Promise<Record<string, unknown>> => {
  const response = await apiFetch(
    `/api/backend/command-results/summary/system/${systemId}?days=${days}`
  );
  return parseOrThrow<Record<string, unknown>>(response, 'Failed to fetch system summary');
};

export const getErrorPatterns = async (
  days = 7,
  systemId?: number
): Promise<ErrorPatternsResponse> => {
  const params = new URLSearchParams();
  params.append('days', String(days));
  if (systemId !== undefined) params.append('system_id', String(systemId));
  const response = await apiFetch(
    `/api/backend/command-results/errors/patterns?${params.toString()}`
  );
  return parseOrThrow<ErrorPatternsResponse>(response, 'Failed to fetch error patterns');
};

export const getPerformanceTrends = async (
  days = 30,
  systemId?: number
): Promise<PerformanceTrendsResponse> => {
  const params = new URLSearchParams();
  params.append('days', String(days));
  if (systemId !== undefined) params.append('system_id', String(systemId));
  const response = await apiFetch(
    `/api/backend/command-results/performance/trends?${params.toString()}`
  );
  return parseOrThrow<PerformanceTrendsResponse>(
    response,
    'Failed to fetch performance trends'
  );
};
