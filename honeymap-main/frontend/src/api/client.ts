import {
  TelemetryEvent,
  AttackerSession,
  MetricsSummary,
  AnalyticsPoint,
  AttackTarget,
  ThreatIntelData,
  SessionTimelineResponse,
  IncidentReport,
} from '../types';

const API_BASE =
  (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_BASE) ||
  'http://localhost:5000';


async function safeFetch<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const res = await fetch(url, options);
  if (!res.ok) {
    throw new Error(`API Error [${res.status}]: ${res.statusText} for ${endpoint}`);
  }
  return res.json() as Promise<T>;
}

export async function fetchHealth(): Promise<{ status: string }> {
  return safeFetch<{ status: string }>('/api/health');
}

export async function fetchEvents(params?: { limit?: number; since?: string }): Promise<{
  status: string;
  events: TelemetryEvent[];
  count: number;
}> {
  const query = new URLSearchParams();
  if (params?.limit) query.set('limit', String(params.limit));
  if (params?.since) query.set('since', params.since);
  const qStr = query.toString();
  return safeFetch(`/api/events${qStr ? `?${qStr}` : ''}`);
}

export async function fetchSessions(params?: { limit?: number }): Promise<{
  status: string;
  sessions: AttackerSession[];
  count: number;
}> {
  const query = new URLSearchParams();
  if (params?.limit) query.set('limit', String(params.limit));
  const qStr = query.toString();
  return safeFetch(`/api/sessions${qStr ? `?${qStr}` : ''}`);
}

export async function fetchMetrics(): Promise<MetricsSummary> {
  return safeFetch<MetricsSummary>('/api/metrics');
}

export async function fetchAnalytics(range: 'day' | 'week' | 'month' | 'year' = 'day'): Promise<{
  status: string;
  range: string;
  points: AnalyticsPoint[];
}> {
  return safeFetch(`/api/analytics?range=${range}`);
}

export async function fetchTargets(): Promise<{
  status: string;
  targets: AttackTarget[];
  count: number;
}> {
  return safeFetch('/api/targets');
}

export async function fetchThreatIntel(): Promise<ThreatIntelData> {
  return safeFetch<ThreatIntelData>('/api/threat-intel');
}

export async function fetchLiveDecoys(): Promise<{
  status: string;
  live_paths: string[];
  pool: string[];
  rotation_cycle: number;
  rotation_interval_seconds: number;
}> {
  return safeFetch('/api/decoys/live');
}


export async function searchTelemetry(q: string): Promise<{
  status: string;
  query: string;
  events: TelemetryEvent[];
  sessions: AttackerSession[];
  total_matches: number;
}> {
  return safeFetch(`/api/search?q=${encodeURIComponent(q)}`);
}

export async function fetchSessionTimeline(sessionId: string): Promise<SessionTimelineResponse> {
  return safeFetch<SessionTimelineResponse>(`/api/session/${encodeURIComponent(sessionId)}/timeline`);
}

export async function fetchIncidentReport(sessionId: string): Promise<{
  status: string;
  report: IncidentReport;
}> {
  return safeFetch(`/api/report/${encodeURIComponent(sessionId)}`);
}

export async function downloadReportJson(sessionId: string): Promise<IncidentReport> {
  const data = await fetchIncidentReport(sessionId);
  const blob = new Blob([JSON.stringify(data.report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `incident-report-${sessionId.slice(0, 8)}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  return data.report;
}

export function blockIpStub(ip: string): { success: boolean; message: string } {
  console.log(`[HoneyMap Firewall Stub] Executed IP Block Rule for: ${ip}`);
  return {
    success: true,
    message: `Firewall block rule queued for ${ip} (SOC Audit Logged)`,
  };
}
