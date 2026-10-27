/**
 * Interpolates Go template tags for immediate sandboxed preview rendering
 * when editing block pages and response templates.
 */
export function interpolateTemplate(
  html: string,
  css: string,
  brand: string,
  logo: string,
  code: number,
  statusText?: string
): string {
  const dummyData: Record<string, string> = {
    '{{.EventID}}': 'evt_9f82c401-d07b-48ae-8f74-2195f32049ba',
    '{{.ClientIP}}': '198.51.100.42',
    '{{.Timestamp}}': new Date().toISOString(),
    '{{.Host}}': 'api.protected-enterprise.io',
    '{{.Path}}': '/v1/graphql/query',
    '{{.BrandName}}': brand || 'Raiwall',
    '{{.LogoURL}}': logo || '',
    '{{.StatusCode}}': String(code),
    '{{.StatusText}}': statusText || 'Security Gate Action',
    '{{.RuleID}}': 'SQLI_UNION_EXTRACT',
  };

  let rendered = html || '<!DOCTYPE html><html><body style="font-family:sans-serif;padding:2rem;"><h1>Blocked</h1></body></html>';
  for (const [tag, val] of Object.entries(dummyData)) {
    rendered = rendered.split(tag).join(val);
  }

  // Templates that own a {{.CustomCSS}} slot get the stylesheet in place; the
  // rest fall back to appending a style block so the preview always carries CSS.
  if (rendered.includes('{{.CustomCSS}}')) {
    rendered = rendered.split('{{.CustomCSS}}').join(css);
  } else if (css) {
    if (rendered.includes('</head>')) {
      rendered = rendered.replace('</head>', `<style>${css}</style></head>`);
    } else {
      rendered = `<style>${css}</style>` + rendered;
    }
  }

  return rendered;
}
