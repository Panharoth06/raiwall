export type ActionType = 'allow' | 'block' | 'challenge' | 'ban';
export type SeverityType = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface GeoData {
  country?: string;
  continent?: string;
  city?: string;
  asn?: number;
  as_org?: string;
  latitude?: number;
  longitude?: number;
}

export interface ForensicEvent {
  event_id: string;
  timestamp: string;
  host: string;
  path: string;
  method: string;
  client_ip: string;
  ja4?: string;
  geo_data?: GeoData;
  rule_id?: string;
  action: ActionType;
  severity: SeverityType;
  headers?: Record<string, string>;
  truncated_payload?: string;
  latency: number;
  status_code: number;
  /** Exact request location of the malicious parameter (URLPATH, QUERY, HEADER, BODY, COOKIE). */
  payload_location?: string;
  /** Isolated malicious syntax token that triggered the verdict. */
  matched_token?: string;
  /** Attack classification category (SQL Injection, XSS, ...). */
  attack_category?: string;
  /** Raw upstream response headers captured for forensic replay. */
  response_headers?: Record<string, string[]>;
  /** Base64-encoded raw upstream response body. */
  response_body?: string;
}

/** Aggregated incident cluster: events sharing client_ip + host within a 5-minute window. */
export interface Incident {
  id: string;
  client_ip: string;
  host: string;
  start_time: string;
  end_time: string;
  total_events: number;
  total_blocked: number;
  category: string;
  max_severity: SeverityType | '';
  top_rule_id: string;
  country?: string;
  sample_event?: ForensicEvent;
}

export interface IncidentQueryResult {
  incidents: Incident[];
  total_count: number;
}

/** Minimal named IP group representation used by forensic triage actions. */
export interface IPGroupOption {
  id: string;
  name: string;
  description?: string;
  type?: string;
  entry_count?: number;
}

/** Copy-to-clipboard lifecycle shared by the forensic drawer and its host. */
export type CurlState = 'idle' | 'loading' | 'copied' | 'error';

export interface TopCount {
  key: string;
  count: number;
}

export interface TimeBucketCount {
  bucket: string;
  total: number;
  block: number;
}

export interface AggregateStats {
  total_requests: number;
  total_blocked: number;
  block_ratio: number;
  page_views?: number;
  unique_visitors?: number;
  unique_ips?: number;
  blocked_ips?: number;
  status_4xx?: number;
  status_4xx_rate?: number;
  status_4xx_blocked?: number;
  status_4xx_blocked_rate?: number;
  status_5xx?: number;
  status_5xx_rate?: number;
  qps?: number;
  time_buckets: TimeBucketCount[];
  top_countries: TopCount[];
  top_rules: TopCount[];
  top_ips: TopCount[];
  top_categories?: TopCount[];
}

export interface ExceptionDraft {
  host: string;
  path: string;
  method: string;
  location: string;
  param: string;
  rule_id: string;
}
