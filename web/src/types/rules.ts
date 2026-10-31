/** Synthetic request evaluated against the live WAF engine. */
export interface RuleTestRequest {
  app_id?: string;
  method?: string;
  host?: string;
  path?: string;
  query?: string;
  client_ip?: string;
  headers?: Record<string, string>;
  body?: string;
  body_base64?: string;
}

export interface RuleTestMatch {
  rule_id: string;
  message?: string;
  severity?: string;
  engine?: string;
}

export interface RuleTestVerdict {
  action: 'allow' | 'block' | 'audit' | 'challenge';
  rule_id?: string;
  reason?: string;
  status_code?: number;
  attack_category?: string;
  engine?: string;
  anomaly_score?: number;
  paranoia_level?: number;
  matched_rules?: RuleTestMatch[];
}

export interface RuleTestResult {
  verdict: RuleTestVerdict;
  duration_ms: number;
}
