export type ViewMode = 'traffic' | 'threats';

export type IngressSourceId = 'bots' | 'humans' | 'api';
export type HumanSubnodeId = 'verified' | 'anonymous';
export type WafHubId = 'waf-core' | 'edge-defense';

export interface TopologyFilterState {
  viewMode: ViewMode;
  owaspOnly: boolean;
  tenant: string;
  timeRange: string;
}

export interface TooltipState {
  visible: boolean;
  x: number;
  y: number;
  header: string;
  subtext: string;
}

export interface IngressSourceNode {
  id: IngressSourceId;
  metric: string;
  title: string;
  subtext: string;
  x: number;
  y: number;
  requestsFormatted: string;
  blockedPercentage: number;
  hoverTelemetry?: string;
}

export interface HumanSubnode {
  id: HumanSubnodeId;
  metric: string;
  title: string;
  subtext: string;
  x: number;
  y: number;
  infoBadge?: boolean;
}

export interface StarburstSpike {
  index: number;
  angle: number;
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  isActive: boolean;
  color: string;
  length: number;
}

export interface WafHubNode {
  id: WafHubId;
  title: string;
  subtitle: string;
  x: number;
  y: number;
  spikes: StarburstSpike[];
}

export interface DestinationSummary {
  count: number | string;
  title: string;
  subtext: string;
  arcType: 'upper' | 'lower';
}

export interface ArcNodeItem {
  id: string;
  label: string;
  category: 'upper' | 'lower';
  x: number;
  y: number;
  isAttackTarget?: boolean;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  tooltipHeader: string;
  tooltipSubtext: string;
}

export interface SankeyRibbon {
  id: string;
  d: string;
  sourceId: string;
  targetId: string;
  stroke: string;
  strokeWidth: number;
  isThreat: boolean;
  dimmed: boolean;
  tooltipHeader: string;
  tooltipSubtext: string;
}

export interface NavRailItem {
  id: string;
  label: string;
  iconName: string;
  active: boolean;
  hasChevron?: boolean;
}
