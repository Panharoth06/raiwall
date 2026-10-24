export type MatchTarget =
  | 'source_ip'
  | 'path'
  | 'host'
  | 'method'
  | 'header'
  | 'query'
  | 'cookie'
  | 'user_agent'
  | 'country';

export type MatchOperator =
  | 'equals'
  | 'not_equals'
  | 'contains'
  | 'not_contains'
  | 'starts_with'
  | 'ends_with'
  | 'in_cidr'
  | 'not_in_cidr'
  | 'in_ip_group'
  | 'not_in_ip_group'
  | 'in_geo'
  | 'not_in_geo'
  | 'regex_match';

export interface VisualCondition {
  id: string;
  target: MatchTarget;
  key?: string;
  operator: MatchOperator;
  content: string;
}

export interface ConditionGroup {
  id: string;
  conditions: VisualCondition[];
}

export interface VisualRuleForm {
  id?: string;
  action: 'allow' | 'block';
  name: string;
  insertPosition: 'first' | 'last';
  priority: number;
  groups: ConditionGroup[];
  continueInspection: boolean;
  enabled: boolean;
  rawExpr: string;
  isAdvancedMode: boolean;
}

export interface TargetOption {
  value: MatchTarget;
  label: string;
  placeholder: string;
  requiresKey?: boolean;
  supportedOperators: MatchOperator[];
}

export interface OperatorOption {
  value: MatchOperator;
  label: string;
}
