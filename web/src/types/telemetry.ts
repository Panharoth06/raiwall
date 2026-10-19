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
}

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
  time_buckets: TimeBucketCount[];
  top_countries: TopCount[];
  top_rules: TopCount[];
  top_ips: TopCount[];
}

export interface ExceptionDraft {
  host: string;
  path: string;
  method: string;
  location: string;
  param: string;
  rule_id: string;
}
