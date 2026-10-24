import { describe, it, expect } from 'vitest';
import {
  conditionToExpr,
  groupsToExpr,
  exprToGroups,
  formatConditionDetail,
} from '../aclRuleTranspiler';
import type { ConditionGroup, VisualCondition } from '@/types/acl';

describe('aclRuleTranspiler', () => {
  describe('conditionToExpr', () => {
    it('transpiles source_ip equals and in_cidr', () => {
      const eqCond: VisualCondition = {
        id: '1',
        target: 'source_ip',
        operator: 'equals',
        content: '192.168.1.10',
      };
      expect(conditionToExpr(eqCond)).toBe('client_ip == "192.168.1.10"');

      const cidrCond: VisualCondition = {
        id: '2',
        target: 'source_ip',
        operator: 'in_cidr',
        content: '10.0.0.0/8',
      };
      expect(conditionToExpr(cidrCond)).toBe('in_cidr(client_ip, "10.0.0.0/8")');
    });

    it('transpiles path operators', () => {
      expect(
        conditionToExpr({
          id: '1',
          target: 'path',
          operator: 'starts_with',
          content: '/admin',
        })
      ).toBe('has_prefix(path, "/admin")');

      expect(
        conditionToExpr({
          id: '2',
          target: 'path',
          operator: 'contains',
          content: 'api',
        })
      ).toBe('str_contains(path, "api")');

      expect(
        conditionToExpr({
          id: '3',
          target: 'path',
          operator: 'not_contains',
          content: 'public',
        })
      ).toBe('!str_contains(path, "public")');

      expect(
        conditionToExpr({
          id: '4',
          target: 'path',
          operator: 'regex_match',
          content: '^/v[0-9]+',
        })
      ).toBe('regex_match("^/v[0-9]+", path)');
    });

    it('transpiles headers with custom key', () => {
      const headerCond: VisualCondition = {
        id: '1',
        target: 'header',
        key: 'X-Api-Key',
        operator: 'equals',
        content: 'secret-123',
      };
      expect(conditionToExpr(headerCond)).toBe('headers["x-api-key"] == "secret-123"');
    });

    it('transpiles query and cookie with keys', () => {
      expect(
        conditionToExpr({
          id: '1',
          target: 'query',
          key: 'action',
          operator: 'equals',
          content: 'debug',
        })
      ).toBe('query["action"] == "debug"');

      expect(
        conditionToExpr({
          id: '2',
          target: 'cookie',
          key: 'session',
          operator: 'not_equals',
          content: 'expired',
        })
      ).toBe('cookies["session"] != "expired"');
    });

    it('transpiles HTTP method and country', () => {
      expect(
        conditionToExpr({
          id: '1',
          target: 'method',
          operator: 'equals',
          content: 'post',
        })
      ).toBe('method == "POST"');

      expect(
        conditionToExpr({
          id: '2',
          target: 'country',
          operator: 'equals',
          content: 'cn',
        })
      ).toBe('geo.country == "CN"');
    });

    it('transpiles source_ip with in_geo and not_in_geo multi-country', () => {
      expect(
        conditionToExpr({
          id: '1',
          target: 'source_ip',
          operator: 'in_geo',
          content: 'US, CN',
        })
      ).toBe('geo.country in ["US", "CN"]');

      expect(
        conditionToExpr({
          id: '2',
          target: 'source_ip',
          operator: 'not_in_geo',
          content: 'DE, FR',
        })
      ).toBe('!(geo.country in ["DE", "FR"])');
    });
  });

  describe('groupsToExpr', () => {
    it('chains multiple conditions within a group with &&', () => {
      const group: ConditionGroup = {
        id: 'g1',
        conditions: [
          { id: '1', target: 'source_ip', operator: 'equals', content: '1.2.3.4' },
          { id: '2', target: 'path', operator: 'starts_with', content: '/admin' },
        ],
      };
      expect(groupsToExpr([group])).toBe('client_ip == "1.2.3.4" && has_prefix(path, "/admin")');
    });

    it('chains multiple groups with || and wraps grouped conditions with parentheses', () => {
      const g1: ConditionGroup = {
        id: 'g1',
        conditions: [
          { id: '1', target: 'source_ip', operator: 'in_cidr', content: '10.0.0.0/8' },
          { id: '2', target: 'method', operator: 'equals', content: 'POST' },
        ],
      };
      const g2: ConditionGroup = {
        id: 'g2',
        conditions: [
          { id: '3', target: 'path', operator: 'equals', content: '/healthz' },
        ],
      };
      expect(groupsToExpr([g1, g2])).toBe(
        '(in_cidr(client_ip, "10.0.0.0/8") && method == "POST") || path == "/healthz"'
      );
    });
  });

  describe('exprToGroups', () => {
    it('parses single condition expression back into groups', () => {
      const parsed = exprToGroups('client_ip == "192.168.1.50"');
      expect(parsed).not.toBeNull();
      expect(parsed?.length).toBe(1);
      expect(parsed?.[0].conditions[0].target).toBe('source_ip');
      expect(parsed?.[0].conditions[0].content).toBe('192.168.1.50');
    });

    it('parses in_cidr and has_prefix combinations', () => {
      const parsed = exprToGroups('in_cidr(client_ip, "10.0.0.0/16") && has_prefix(path, "/api")');
      expect(parsed).not.toBeNull();
      expect(parsed?.length).toBe(1);
      expect(parsed?.[0].conditions.length).toBe(2);
      expect(parsed?.[0].conditions[0].operator).toBe('in_cidr');
      expect(parsed?.[0].conditions[1].operator).toBe('starts_with');
    });

    it('parses geo.country in [...] and !(geo.country in [...])', () => {
      const parsed = exprToGroups('geo.country in ["US", "CN"]');
      expect(parsed).not.toBeNull();
      expect(parsed?.[0].conditions[0].operator).toBe('in_geo');
      expect(parsed?.[0].conditions[0].content).toBe('US, CN');

      const parsedNeg = exprToGroups('!(geo.country in ["DE", "FR"])');
      expect(parsedNeg).not.toBeNull();
      expect(parsedNeg?.[0].conditions[0].operator).toBe('not_in_geo');
      expect(parsedNeg?.[0].conditions[0].content).toBe('DE, FR');
    });

    it('returns null on complex non-standard expr requiring advanced mode', () => {
      const parsed = exprToGroups('custom_unknown_fn(123) + 45');
      expect(parsed).toBeNull();
    });
  });

  describe('formatConditionDetail', () => {
    it('formats readable chips with connector tags', () => {
      const chips = formatConditionDetail(
        'client_ip == "1.2.3.4" && has_prefix(path, "/admin")'
      );
      expect(chips.length).toBe(3);
      expect(chips[0].text).toContain('Source IP == "1.2.3.4"');
      expect(chips[1].text).toBe('AND');
      expect(chips[1].isConnector).toBe(true);
      expect(chips[2].text).toContain('URL Path Starts With "/admin"');
    });
  });
});
