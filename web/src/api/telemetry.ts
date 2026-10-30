import { request } from './client';
import type { IncidentQueryResult, IPGroupOption, AggregateStats, GeoIPStatus } from '@/types/telemetry';

export interface StatsQueryParams {
  start_time?: string;
  end_time?: string;
  host?: string;
  country?: string;
}

export interface IncidentQueryParams {
  start_time?: string;
  end_time?: string;
  client_ip?: string;
  host?: string;
  limit?: number;
  offset?: number;
}

export interface CurlExport {
  curl: string;
}

/** Forensic triage endpoints: incident clustering, cURL replay and IP group mutation. */
export const telemetryApi = {
  getStats: (params: StatsQueryParams = {}) => {
    const q = new URLSearchParams();
    if (params.start_time) q.set('start_time', params.start_time);
    if (params.end_time) q.set('end_time', params.end_time);
    if (params.host) q.set('host', params.host);
    if (params.country) q.set('country', params.country);
    const qs = q.toString();
    return request<AggregateStats>(`/telemetry/events/stats${qs ? '?' + qs : ''}`);
  },

  listIncidents: (params: IncidentQueryParams = {}) => {
    const q = new URLSearchParams();
    if (params.start_time) q.set('start_time', params.start_time);
    if (params.end_time) q.set('end_time', params.end_time);
    if (params.client_ip) q.set('client_ip', params.client_ip);
    if (params.host) q.set('host', params.host);
    if (params.limit != null) q.set('limit', String(params.limit));
    if (params.offset != null) q.set('offset', String(params.offset));
    const qs = q.toString();
    return request<IncidentQueryResult>(`/telemetry/incidents${qs ? '?' + qs : ''}`);
  },

  getEventCurl: (eventId: string) =>
    request<CurlExport>(`/telemetry/events/${encodeURIComponent(eventId)}/curl`),

  listIPGroups: () => request<IPGroupOption[]>('/ip-groups'),

  /** GeoIP database availability, used to explain an empty country breakdown. */
  getGeoIPStatus: () => request<GeoIPStatus>('/telemetry/geoip'),

  addIPGroupEntry: (groupId: string, cidr: string, comment: string) =>
    request<{ id: string; group_id: string; cidr: string }>(
      `/ip-groups/${encodeURIComponent(groupId)}/entries`,
      { method: 'POST', body: JSON.stringify({ cidr, comment }) }
    ),
};
