export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface GeoIPData {
  ip: string;
  country: string;
  country_code: string;
  city: string;
  latitude: number;
  longitude: number;
  asn?: string;
  org?: string;
}

export interface TelemetryEvent {
  id: number;
  session_id?: string | null;
  timestamp: string;
  source_ip: string;
  source_port?: number;
  request_method?: string;
  endpoint: string;
  headers_json?: string;
  payload?: string;
  attack_type?: string;
  severity: Severity;
  flagged_token?: string | null;
  metadata_json?: string;
  geoip?: GeoIPData | null;
  ip?: string;
  path?: string;
  reason?: string;
  lat?: number | null;
  lon?: number | null;
}

export interface AttackerSession {
  session_id: string;
  source_ip: string;
  first_seen: string;
  last_seen: string;
  user_agent?: string;
  request_count: number;
  max_severity: Severity;
  notes?: string;
  score?: number;
  decayed_score?: number;
  event_count?: number;
  geoip?: GeoIPData | null;
}

export interface MetricsSummary {
  critical_threats: number;
  requests_blocked: number;
  active_incidents: number;
  total_requests: number;
  severity_breakdown: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
}

export interface AnalyticsPoint {
  bucket: string;
  normal: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
  total: number;
}

export interface AttackTarget {
  target: string;
  incidents: number;
  requests: number;
  severity: Severity;
  trend: number;
  last_seen?: string | null;
}

export interface HoneytokenItem {
  token_id: string;
  token_type: string;
  token_value: string;
  description?: string | null;
  created_at?: string | null;
  trigger_count: number;
  last_triggered?: string | null;
  is_active: boolean;
}

export interface ThreatIntelData {
  active_tokens: Record<string, string>;
  tokens: HoneytokenItem[];
  compromised_events: TelemetryEvent[];
  total_compromised_count: number;
}

export interface SessionTimelineResponse {
  status: string;
  session_id: string;
  session?: AttackerSession;
  geoip?: GeoIPData;
  events: TelemetryEvent[];
  event_count: number;
}

export interface IncidentReport {
  report_id: string;
  generated_at: string;
  session_id: string;
  attacker: {
    source_ip: string;
    user_agent?: string;
    geoip?: GeoIPData;
    threat_score: number;
    max_severity: Severity;
    total_requests: number;
    first_seen: string;
    last_seen: string;
  };
  executive_summary: {
    criticality: string;
    target_count: number;
    targeted_endpoints: string[];
    attack_tactics_observed: string[];
    honeytokens_compromised: string[];
  };
  timeline_events: Array<{
    event_id: number;
    timestamp: string;
    method?: string;
    endpoint: string;
    attack_type?: string;
    severity: Severity;
    flagged_token?: string | null;
  }>;
  narrative_analysis?: string | null;
}
