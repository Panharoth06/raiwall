import type {
  MatchTarget,
  MatchOperator,
  VisualCondition,
  ConditionGroup,
  TargetOption,
  OperatorOption,
} from '@/types/acl';

export const TARGET_OPTIONS: TargetOption[] = [
  {
    value: 'source_ip',
    label: 'Source IP',
    placeholder: 'e.g: 192.168.10.10 or 10.0.0.0/24',
    supportedOperators: [
      'equals',
      'not_equals',
      'in_cidr',
      'not_in_cidr',
      'in_ip_group',
      'not_in_ip_group',
      'in_geo',
      'not_in_geo',
    ],
  },
  {
    value: 'path',
    label: 'URL Path',
    placeholder: 'e.g: /admin or /api/v1/auth',
    supportedOperators: [
      'equals',
      'not_equals',
      'starts_with',
      'contains',
      'not_contains',
      'regex_match',
    ],
  },
  {
    value: 'host',
    label: 'Host / Domain',
    placeholder: 'e.g: api.example.com',
    supportedOperators: ['equals', 'not_equals', 'starts_with', 'contains'],
  },
  {
    value: 'method',
    label: 'HTTP Method',
    placeholder: 'e.g: POST, GET, DELETE',
    supportedOperators: ['equals', 'not_equals'],
  },
  {
    value: 'header',
    label: 'HTTP Header',
    placeholder: 'e.g: Bearer token... or gzip',
    requiresKey: true,
    supportedOperators: ['equals', 'not_equals', 'contains', 'not_contains', 'starts_with', 'regex_match'],
  },
  {
    value: 'query',
    label: 'Query Parameter',
    placeholder: 'e.g: search_query',
    requiresKey: true,
    supportedOperators: ['equals', 'not_equals', 'contains', 'not_contains', 'starts_with'],
  },
  {
    value: 'cookie',
    label: 'Cookie Value',
    placeholder: 'e.g: session_token',
    requiresKey: true,
    supportedOperators: ['equals', 'not_equals', 'contains', 'not_contains'],
  },
  {
    value: 'user_agent',
    label: 'User-Agent',
    placeholder: 'e.g: python-requests or curl',
    supportedOperators: ['contains', 'not_contains', 'equals', 'not_equals', 'regex_match'],
  },
  {
    value: 'country',
    label: 'Country (GeoIP)',
    placeholder: 'Select country / region...',
    supportedOperators: ['in_geo', 'not_in_geo', 'equals', 'not_equals'],
  },
];

export const OPERATOR_LABELS: Record<MatchOperator, string> = {
  equals: 'Equals',
  not_equals: 'Does Not Equal',
  contains: 'Contains',
  not_contains: 'Does Not Contain',
  starts_with: 'Starts With',
  ends_with: 'Ends With',
  in_cidr: 'In CIDR',
  not_in_cidr: 'Does Not In CIDR',
  in_ip_group: 'In IP Group',
  not_in_ip_group: 'Does Not In IP Group',
  in_geo: 'In Geo Location',
  not_in_geo: 'Not In Geo Location',
  regex_match: 'Matches Regex',
};

export const OPERATOR_OPTIONS: OperatorOption[] = (
  Object.keys(OPERATOR_LABELS) as MatchOperator[]
).map((key) => ({
  value: key,
  label: OPERATOR_LABELS[key],
}));

export function getTargetConfig(target: MatchTarget): TargetOption {
  return TARGET_OPTIONS.find((t) => t.value === target) || TARGET_OPTIONS[0];
}

function escapeString(val: string): string {
  return val.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/**
 * Transpiles a single visual condition into an expr-lang expression string.
 */
export function conditionToExpr(c: VisualCondition): string {
  const content = escapeString(c.content.trim());
  const key = c.key ? escapeString(c.key.trim().toLowerCase()) : '';

  switch (c.target) {
    case 'source_ip':
      if (c.operator === 'in_geo' || c.operator === 'not_in_geo') {
        const codes = c.content.split(',').map((s) => s.trim().toUpperCase()).filter(Boolean);
        if (c.operator === 'in_geo') {
          return codes.length === 1
            ? `geo.country == "${codes[0]}"`
            : `geo.country in [${codes.map((x) => `"${x}"`).join(', ')}]`;
        } else {
          return codes.length === 1
            ? `geo.country != "${codes[0]}"`
            : `!(geo.country in [${codes.map((x) => `"${x}"`).join(', ')}])`;
        }
      }
      if (c.operator === 'in_cidr') {
        return `in_cidr(client_ip, "${content}")`;
      }
      if (c.operator === 'not_in_cidr') {
        return `!in_cidr(client_ip, "${content}")`;
      }
      if (c.operator === 'in_ip_group') {
        return `client_ip in ip_group("${content}")`;
      }
      if (c.operator === 'not_in_ip_group') {
        return `!(client_ip in ip_group("${content}"))`;
      }
      if (c.operator === 'not_equals') {
        return `client_ip != "${content}"`;
      }
      return `client_ip == "${content}"`;

    case 'path':
      if (c.operator === 'starts_with') {
        return `has_prefix(path, "${content}")`;
      }
      if (c.operator === 'contains') {
        return `str_contains(path, "${content}")`;
      }
      if (c.operator === 'not_contains') {
        return `!str_contains(path, "${content}")`;
      }
      if (c.operator === 'regex_match') {
        return `regex_match("${content}", path)`;
      }
      if (c.operator === 'not_equals') {
        return `path != "${content}"`;
      }
      return `path == "${content}"`;

    case 'host':
      if (c.operator === 'starts_with') {
        return `has_prefix(host, "${content}")`;
      }
      if (c.operator === 'contains') {
        return `str_contains(host, "${content}")`;
      }
      if (c.operator === 'not_equals') {
        return `host != "${content}"`;
      }
      return `host == "${content}"`;

    case 'method':
      if (c.operator === 'not_equals') {
        return `method != "${content.toUpperCase()}"`;
      }
      return `method == "${content.toUpperCase()}"`;

    case 'header': {
      const headerRef = `headers["${key || 'content-type'}"]`;
      if (c.operator === 'contains') {
        return `str_contains(${headerRef}, "${content}")`;
      }
      if (c.operator === 'not_contains') {
        return `!str_contains(${headerRef}, "${content}")`;
      }
      if (c.operator === 'starts_with') {
        return `has_prefix(${headerRef}, "${content}")`;
      }
      if (c.operator === 'regex_match') {
        return `regex_match("${content}", ${headerRef})`;
      }
      if (c.operator === 'not_equals') {
        return `${headerRef} != "${content}"`;
      }
      return `${headerRef} == "${content}"`;
    }

    case 'query': {
      const queryRef = `query["${key}"]`;
      if (c.operator === 'contains') {
        return `str_contains(${queryRef}, "${content}")`;
      }
      if (c.operator === 'not_contains') {
        return `!str_contains(${queryRef}, "${content}")`;
      }
      if (c.operator === 'not_equals') {
        return `${queryRef} != "${content}"`;
      }
      return `${queryRef} == "${content}"`;
    }

    case 'cookie': {
      const cookieRef = `cookies["${key}"]`;
      if (c.operator === 'contains') {
        return `str_contains(${cookieRef}, "${content}")`;
      }
      if (c.operator === 'not_contains') {
        return `!str_contains(${cookieRef}, "${content}")`;
      }
      if (c.operator === 'not_equals') {
        return `${cookieRef} != "${content}"`;
      }
      return `${cookieRef} == "${content}"`;
    }

    case 'user_agent':
      if (c.operator === 'not_contains') {
        return `!str_contains(user_agent, "${content}")`;
      }
      if (c.operator === 'equals') {
        return `user_agent == "${content}"`;
      }
      if (c.operator === 'not_equals') {
        return `user_agent != "${content}"`;
      }
      if (c.operator === 'regex_match') {
        return `regex_match("${content}", user_agent)`;
      }
      return `str_contains(user_agent, "${content}")`;

    case 'country': {
      const codes = c.content.split(',').map((s) => s.trim().toUpperCase()).filter(Boolean);
      if (c.operator === 'not_in_geo' || c.operator === 'not_equals') {
        return codes.length === 1
          ? `geo.country != "${codes[0]}"`
          : `!(geo.country in [${codes.map((x) => `"${x}"`).join(', ')}])`;
      }
      return codes.length === 1
        ? `geo.country == "${codes[0]}"`
        : `geo.country in [${codes.map((x) => `"${x}"`).join(', ')}]`;
    }

    default:
      return `path == "${content}"`;
  }
}

/**
 * Transpiles groups of conditions into a full expr expression.
 * Inner conditions are AND-ed, outer groups are OR-ed.
 */
export function groupsToExpr(groups: ConditionGroup[]): string {
  const validGroups = groups
    .map((g) =>
      g.conditions
        .filter((c) => c.content.trim() !== '')
        .map(conditionToExpr)
    )
    .filter((g) => g.length > 0);

  if (validGroups.length === 0) {
    return 'true';
  }

  const groupExprs = validGroups.map((groupConditions) => {
    if (groupConditions.length === 1) {
      return groupConditions[0];
    }
    return groupConditions.join(' && ');
  });

  if (groupExprs.length === 1) {
    return groupExprs[0];
  }

  return groupExprs.map((e) => (e.includes('&&') ? `(${e})` : e)).join(' || ');
}

/**
 * Attempts to parse an expr expression into visual condition groups.
 * Returns null if the expression is too complex or non-standard, triggering Advanced Mode.
 */
export function exprToGroups(rawExpr: string): ConditionGroup[] | null {
  const trimmed = rawExpr.trim();
  if (!trimmed) {
    return [
      {
        id: 'group-1',
        conditions: [
          {
            id: 'cond-1',
            target: 'source_ip',
            operator: 'equals',
            content: '',
          },
        ],
      },
    ];
  }

  // Split by top-level OR (' || ')
  const orParts = trimmed.split(/\s*\|\|\s*/);
  const groups: ConditionGroup[] = [];

  for (let gIdx = 0; gIdx < orParts.length; gIdx++) {
    let part = orParts[gIdx].trim();
    if (part.startsWith('(') && part.endsWith(')')) {
      part = part.slice(1, -1).trim();
    }

    const andParts = part.split(/\s*&&\s*/);
    const conditions: VisualCondition[] = [];

    for (let cIdx = 0; cIdx < andParts.length; cIdx++) {
      const condStr = andParts[cIdx].trim();
      const parsed = parseSingleCondition(condStr, `${gIdx}-${cIdx}`);
      if (!parsed) {
        return null; // Cannot parse cleanly, trigger advanced mode
      }
      conditions.push(parsed);
    }

    if (conditions.length > 0) {
      groups.push({
        id: `group-${gIdx + 1}`,
        conditions,
      });
    }
  }

  return groups.length > 0 ? groups : null;
}

function parseSingleCondition(str: string, idSuffix: string): VisualCondition | null {
  // 1. geo.country in [...] or !(geo.country in [...])
  let m = str.match(/^(!?)\(?geo\.country\s+in\s+\[(.*?)\]\)?$/);
  if (m) {
    const isNeg = m[1] === '!';
    const codes = m[2]
      .split(',')
      .map((s) => s.replace(/["'\s]/g, ''))
      .filter(Boolean);
    return {
      id: `cond-${idSuffix}`,
      target: 'source_ip',
      operator: isNeg ? 'not_in_geo' : 'in_geo',
      content: codes.join(', '),
    };
  }

  // 2. geo.country == / != "..."
  m = str.match(/^geo\.country\s*(==|!=)\s*"([^"]+)"$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'source_ip',
      operator: m[1] === '!=' ? 'not_in_geo' : 'in_geo',
      content: m[2],
    };
  }

  // 3. !in_cidr(client_ip, "...")
  m = str.match(/^!in_cidr\((?:client_ip|ip),\s*"([^"]+)"\)$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'source_ip',
      operator: 'not_in_cidr',
      content: m[1],
    };
  }

  // 4. in_cidr(client_ip, "...")
  m = str.match(/^in_cidr\((?:client_ip|ip),\s*"([^"]+)"\)$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'source_ip',
      operator: 'in_cidr',
      content: m[1],
    };
  }

  // 5. client_ip in ip_group("...") or !(client_ip in ip_group("..."))
  m = str.match(/^(!?)\(?(?:client_ip|ip)\s+in\s+ip_group\("([^"]+)"\)\)?$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'source_ip',
      operator: m[1] === '!' ? 'not_in_ip_group' : 'in_ip_group',
      content: m[2],
    };
  }

  // 6. client_ip / ip == or != "..."
  m = str.match(/^(?:client_ip|ip)\s*(==|!=)\s*"([^"]+)"$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'source_ip',
      operator: m[1] === '!=' ? 'not_equals' : 'equals',
      content: m[2],
    };
  }

  // 3. path == / !=
  m = str.match(/^path\s*(==|!=)\s*"([^"]+)"$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'path',
      operator: m[1] === '!=' ? 'not_equals' : 'equals',
      content: m[2],
    };
  }

  // 4. has_prefix(path, "...")
  m = str.match(/^has_prefix\(path,\s*"([^"]+)"\)$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'path',
      operator: 'starts_with',
      content: m[1],
    };
  }

  // 5. str_contains(path, "...") or !str_contains(...)
  m = str.match(/^(!?)str_contains\(path,\s*"([^"]+)"\)$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'path',
      operator: m[1] === '!' ? 'not_contains' : 'contains',
      content: m[2],
    };
  }

  // 6. regex_match("...", path)
  m = str.match(/^regex_match\("([^"]+)",\s*path\)$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'path',
      operator: 'regex_match',
      content: m[1],
    };
  }

  // 7. host == / !=
  m = str.match(/^host\s*(==|!=)\s*"([^"]+)"$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'host',
      operator: m[1] === '!=' ? 'not_equals' : 'equals',
      content: m[2],
    };
  }

  // 8. has_prefix(host, "...") / str_contains(host, "...")
  m = str.match(/^has_prefix\(host,\s*"([^"]+)"\)$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'host',
      operator: 'starts_with',
      content: m[1],
    };
  }
  m = str.match(/^str_contains\(host,\s*"([^"]+)"\)$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'host',
      operator: 'contains',
      content: m[1],
    };
  }

  // 9. method == / !=
  m = str.match(/^method\s*(==|!=)\s*"([^"]+)"$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'method',
      operator: m[1] === '!=' ? 'not_equals' : 'equals',
      content: m[2],
    };
  }

  // 10. headers["key"] == / !=
  m = str.match(/^headers\["([^"]+)"\]\s*(==|!=)\s*"([^"]+)"$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'header',
      key: m[1],
      operator: m[2] === '!=' ? 'not_equals' : 'equals',
      content: m[3],
    };
  }

  // 11. str_contains(headers["key"], "...")
  m = str.match(/^(!?)str_contains\(headers\["([^"]+)"\],\s*"([^"]+)"\)$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'header',
      key: m[2],
      operator: m[1] === '!' ? 'not_contains' : 'contains',
      content: m[3],
    };
  }

  // 12. user_agent contains / not contains / equals
  m = str.match(/^(!?)str_contains\(user_agent,\s*"([^"]+)"\)$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'user_agent',
      operator: m[1] === '!' ? 'not_contains' : 'contains',
      content: m[2],
    };
  }
  m = str.match(/^user_agent\s*(==|!=)\s*"([^"]+)"$/);
  if (m) {
    return {
      id: `cond-${idSuffix}`,
      target: 'user_agent',
      operator: m[1] === '!=' ? 'not_equals' : 'equals',
      content: m[2],
    };
  }


  return null;
}

/**
 * Creates friendly human-readable summary badges for table rendering.
 */
export function formatConditionDetail(expr: string): { text: string; isConnector?: boolean }[] {
  if (!expr || expr === 'true') {
    return [{ text: 'Match All Requests' }];
  }

  const groups = exprToGroups(expr);
  if (!groups) {
    // Return formatted raw expression
    return [{ text: expr }];
  }

  const chips: { text: string; isConnector?: boolean }[] = [];

  groups.forEach((group, gIdx) => {
    if (gIdx > 0) {
      chips.push({ text: 'OR', isConnector: true });
    }

    group.conditions.forEach((c, cIdx) => {
      if (cIdx > 0) {
        chips.push({ text: 'AND', isConnector: true });
      }

      const targetLabel = TARGET_OPTIONS.find((t) => t.value === c.target)?.label || c.target;
      const opLabel = c.operator === 'equals' ? '==' : c.operator === 'not_equals' ? '!=' : OPERATOR_LABELS[c.operator];
      const keySuffix = c.key ? `[${c.key}]` : '';

      chips.push({
        text: `${targetLabel}${keySuffix} ${opLabel} "${c.content}"`,
      });
    });
  });

  return chips;
}
