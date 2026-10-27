package templates

const template403HTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.StatusCode}} {{.StatusText}} - {{.BrandName}}</title>
  <style>{{.CustomCSS}}</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">{{.BrandName}} Web Application Firewall</div>
      <div class="status-badge">HTTP {{.StatusCode}}</div>
    </div>
    <h1 class="title">Security Violation Detected - Request Blocked</h1>
    <p class="description">Your request was flagged and blocked due to security violations in accordance with active threat defense policies. If you believe this is a false positive, please contact the site administrator with the Event ID below.</p>
    <div class="meta-grid">
      <div class="meta-item"><span class="meta-label">Event ID</span><span class="meta-val">{{.EventID}}</span></div>
      <div class="meta-item"><span class="meta-label">Client IP</span><span class="meta-val">{{.ClientIP}}</span></div>
      <div class="meta-item"><span class="meta-label">Host</span><span class="meta-val">{{.Host}}</span></div>
      <div class="meta-item"><span class="meta-label">Timestamp</span><span class="meta-val">{{.Timestamp}}</span></div>
    </div>
    <div class="footer">Protected by {{.BrandName}} Enterprise Gateway</div>
  </div>
</body>
</html>`

const template404HTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>404 Not Found - {{.BrandName}}</title>
  <style>{{.CustomCSS}}</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">{{.BrandName}} Gateway</div>
      <div class="status-badge" style="color: #a8a8a8; border-color: #2e2e2e; background: #1f1f1f;">HTTP 404</div>
    </div>
    <h1 class="title">Resource Not Found</h1>
    <p class="description">The requested URI path does not exist on this server or has been relocated.</p>
    <div class="meta-grid">
      <div class="meta-item"><span class="meta-label">Path</span><span class="meta-val">{{.Path}}</span></div>
      <div class="meta-item"><span class="meta-label">Client IP</span><span class="meta-val">{{.ClientIP}}</span></div>
    </div>
    <div class="footer">&copy; {{.BrandName}} Gateway</div>
  </div>
</body>
</html>`

const template429HTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>429 Too Many Requests - {{.BrandName}}</title>
  <style>{{.CustomCSS}}</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">{{.BrandName}} Rate Limiter</div>
      <div class="status-badge" style="color: #f59e0b; border-color: rgba(245, 158, 11, 0.3); background: rgba(245, 158, 11, 0.15);">HTTP 429</div>
    </div>
    <h1 class="title">Request Velocity Exceeded</h1>
    <p class="description">You have sent too many requests in a short period of time. Please pause your requests and try again shortly.</p>
    <div class="meta-grid">
      <div class="meta-item"><span class="meta-label">Client IP</span><span class="meta-val">{{.ClientIP}}</span></div>
      <div class="meta-item"><span class="meta-label">Timestamp</span><span class="meta-val">{{.Timestamp}}</span></div>
    </div>
    <div class="footer">Protected by {{.BrandName}} Rate Limiter</div>
  </div>
</body>
</html>`

const template465HTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Waiting Room - {{.BrandName}}</title>
  <style>{{.CustomCSS}}</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">{{.BrandName}} Virtual Waiting Room</div>
      <div class="status-badge" style="color: #22d3ee; border-color: rgba(34, 211, 238, 0.3); background: rgba(34, 211, 238, 0.15);">HTTP 465</div>
    </div>
    <h1 class="title">You are in the Queue</h1>
    <p class="description">We are experiencing heavy traffic. You will automatically be admitted as capacity opens up. Please do not close or refresh this page.</p>
    <div class="meta-grid">
      <div class="meta-item"><span class="meta-label">Queue Ticket</span><span class="meta-val">{{.EventID}}</span></div>
      <div class="meta-item"><span class="meta-label">Status</span><span class="meta-val">Buffering Traffic</span></div>
    </div>
    <div class="footer">{{.BrandName}} Traffic Queue</div>
  </div>
</body>
</html>`

const template466HTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Application Offline - {{.BrandName}}</title>
  <style>{{.CustomCSS}}</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">{{.BrandName}} Gateway</div>
      <div class="status-badge" style="color: #a8a8a8; border-color: #2e2e2e; background: #1f1f1f;">HTTP 466</div>
    </div>
    <h1 class="title">Service Offline for Maintenance</h1>
    <p class="description">This application is temporarily set to offline mode by system administrators. Please check back later.</p>
    <div class="meta-grid">
      <div class="meta-item"><span class="meta-label">Host</span><span class="meta-val">{{.Host}}</span></div>
      <div class="meta-item"><span class="meta-label">Timestamp</span><span class="meta-val">{{.Timestamp}}</span></div>
    </div>
    <div class="footer">&copy; {{.BrandName}}</div>
  </div>
</body>
</html>`

const template467HTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Zero-Trust Authentication - {{.BrandName}}</title>
  <style>{{.CustomCSS}}</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">{{.BrandName}} Identity Gateway</div>
      <div class="status-badge" style="color: #10b981; border-color: rgba(16, 185, 129, 0.3); background: rgba(16, 185, 129, 0.15);">HTTP 467</div>
    </div>
    <h1 class="title">Authentication Required</h1>
    <p class="description">This domain requires verified credentials before access is granted to backend services.</p>
    <div class="meta-grid">
      <div class="meta-item"><span class="meta-label">Target URI</span><span class="meta-val">{{.Path}}</span></div>
      <div class="meta-item"><span class="meta-label">Client IP</span><span class="meta-val">{{.ClientIP}}</span></div>
    </div>
    <div class="footer">{{.BrandName}} Zero-Trust Gateway</div>
  </div>
</body>
</html>`

const template468HTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bot Verification - {{.BrandName}}</title>
  <style>{{.CustomCSS}}</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">{{.BrandName}} Bot Defense</div>
      <div class="status-badge" style="color: #8b5cf6; border-color: rgba(139, 92, 246, 0.3); background: rgba(139, 92, 246, 0.15);">HTTP 468</div>
    </div>
    <h1 class="title">Security Check in Progress</h1>
    <p class="description">Your browser is performing a fast cryptographic proof-of-work computation to verify you are a genuine human user.</p>
    <div class="meta-grid">
      <div class="meta-item"><span class="meta-label">Client IP</span><span class="meta-val">{{.ClientIP}}</span></div>
      <div class="meta-item"><span class="meta-label">Challenge</span><span class="meta-val">SHA-256 Proof of Work</span></div>
    </div>
    <div class="footer">{{.BrandName}} Active Defense</div>
  </div>
</body>
</html>`

const template502HTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>502 Bad Gateway - {{.BrandName}}</title>
  <style>{{.CustomCSS}}</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">{{.BrandName}} Reverse Proxy</div>
      <div class="status-badge" style="color: #ef4444; border-color: rgba(239, 68, 68, 0.3); background: rgba(239, 68, 68, 0.15);">HTTP 502</div>
    </div>
    <h1 class="title">Bad Gateway</h1>
    <p class="description">The reverse proxy gateway was unable to connect to the upstream backend service. The application server may be down or unreachable.</p>
    <div class="meta-grid">
      <div class="meta-item"><span class="meta-label">Host</span><span class="meta-val">{{.Host}}</span></div>
      <div class="meta-item"><span class="meta-label">Timestamp</span><span class="meta-val">{{.Timestamp}}</span></div>
    </div>
    <div class="footer">&copy; {{.BrandName}} Gateway</div>
  </div>
</body>
</html>`

const template504HTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>504 Gateway Timeout - {{.BrandName}}</title>
  <style>{{.CustomCSS}}</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">{{.BrandName}} Reverse Proxy</div>
      <div class="status-badge" style="color: #f59e0b; border-color: rgba(245, 158, 11, 0.3); background: rgba(245, 158, 11, 0.15);">HTTP 504</div>
    </div>
    <h1 class="title">Gateway Timeout</h1>
    <p class="description">The upstream backend service did not return a response within the configured timeout window.</p>
    <div class="meta-grid">
      <div class="meta-item"><span class="meta-label">Host</span><span class="meta-val">{{.Host}}</span></div>
      <div class="meta-item"><span class="meta-label">Timestamp</span><span class="meta-val">{{.Timestamp}}</span></div>
    </div>
    <div class="footer">&copy; {{.BrandName}} Gateway</div>
  </div>
</body>
</html>`
