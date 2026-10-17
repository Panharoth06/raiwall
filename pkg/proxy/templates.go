package proxy

const defaultBlockHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>403 Forbidden - Raiwall Protection</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
.card { background: #1e293b; padding: 2.5rem; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); max-width: 500px; text-align: center; border: 1px solid #334155; }
.badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; background: #ef4444; color: #fff; font-size: 0.875rem; font-weight: 600; margin-bottom: 1rem; }
h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
p { color: #94a3b8; font-size: 0.95rem; line-height: 1.5; }
.footer { margin-top: 1.5rem; font-size: 0.8rem; color: #64748b; border-top: 1px solid #334155; padding-top: 1rem; }
</style>
</head>
<body>
<div class="card">
<div class="badge">Blocked by WAF</div>
<h1>Request Blocked</h1>
<p>Your request has been identified as potential malicious activity and blocked by Raiwall Web Application Firewall.</p>
<div class="footer">Event ID: {{EVENT_ID}} &bull; Protected by Raiwall</div>
</div>
</body>
</html>`

const defaultOfflineHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>503 Service Unavailable - Maintenance</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
.card { background: #1e293b; padding: 2.5rem; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); max-width: 500px; text-align: center; border: 1px solid #334155; }
.badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; background: #f59e0b; color: #000; font-size: 0.875rem; font-weight: 600; margin-bottom: 1rem; }
h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
p { color: #94a3b8; font-size: 0.95rem; line-height: 1.5; }
.footer { margin-top: 1.5rem; font-size: 0.8rem; color: #64748b; border-top: 1px solid #334155; padding-top: 1rem; }
</style>
</head>
<body>
<div class="card">
<div class="badge">Maintenance Mode</div>
<h1>Under Scheduled Maintenance</h1>
<p>This service is currently offline for scheduled maintenance. Please check back shortly.</p>
<div class="footer">Protected by Raiwall Gateway</div>
</div>
</body>
</html>`
