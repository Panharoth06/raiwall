package auth

import (
	"fmt"
	"strings"
)

// challengeTemplateData drives the zero-trust HTTP 467 login portal.
type challengeTemplateData struct {
	AppID      string
	Host       string
	Target     string
	ClientIP   string
	ErrorMsg   string
	LoginPath  string
	TOTPNeeded bool
}

// renderChallengeTemplate streams the zero-CDN dark-mode pre-app auth portal.
func renderChallengeTemplate(d challengeTemplateData) string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authentication Required — ` + d.Host + `</title>
<style>
  :root { color-scheme: dark; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: ui-sans-serif, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #0d1117; color: #e6edf3; min-height: 100vh;
    display: flex; align-items: center; justify-content: center; padding: 24px;
  }
  .portal {
    width: 100%; max-width: 380px; background: #161b22; border: 1px solid #30363d;
    border-radius: 12px; padding: 28px 26px;
  }
  .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 20px; }
  .brand-glyph {
    width: 30px; height: 30px; border-radius: 7px; background: #1f6feb;
    display: flex; align-items: center; justify-content: center;
    font-weight: 700; font-size: 13px; color: #fff;
  }
  .brand-name { font-size: 13px; font-weight: 600; letter-spacing: 0.04em; color: #9198a1; text-transform: uppercase; }
  .code-badge {
    font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 11px;
    color: #3fb950; border: 1px solid rgba(63,185,80,0.4); background: rgba(63,185,80,0.12);
    border-radius: 999px; padding: 2px 9px; margin-left: auto;
  }
  h1 { font-size: 18px; margin-bottom: 8px; }
  .meta { font-size: 12.5px; color: #8b949e; line-height: 1.55; margin-bottom: 18px; word-break: break-word; }
  .meta code { color: #79c0ff; font-size: 11.5px; }
  label { display: block; font-size: 11px; font-weight: 600; letter-spacing: 0.03em;
          text-transform: uppercase; color: #9198a1; margin: 14px 0 6px; }
  input[type=text], input[type=password] {
    width: 100%; background: #0d1117; border: 1px solid #30363d; color: #e6edf3;
    border-radius: 6px; padding: 9px 10px; font-size: 14px; outline: none;
  }
  input:focus { border-color: #1f6feb; box-shadow: 0 0 0 3px rgba(31,111,235,0.25); }
  button {
    width: 100%; margin-top: 20px; background: #1f6feb; color: #fff; border: 0;
    border-radius: 6px; padding: 10px; font-size: 14px; font-weight: 600; cursor: pointer;
  }
  button:hover { background: #388bfd; }
  .error-banner {
    background: rgba(248,81,73,0.12); border: 1px solid rgba(248,81,73,0.4);
    color: #f85149; border-radius: 6px; padding: 9px 11px; font-size: 13px; margin-top: 16px;
  }
  .footnote { margin-top: 18px; font-size: 11.5px; color: #6e7681; line-height: 1.5; }
</style>
</head>
<body>
<main class="portal">
  <div class="brand">
    <div class="brand-glyph">R</div>
    <div class="brand-name">Raiwall Identity Gateway</div>
    <span class="code-badge">HTTP 467</span>
  </div>
  <h1>Authentication required</h1>
  <p class="meta">Host <code>` + d.Host + `</code> requires verified credentials.<br>
     Challenge applies to site <code>` + d.AppID + `</code> · client ` + d.ClientIP + `.</p>
  <form method="POST" action="` + d.LoginPath + `">
    <input type="hidden" name="redirect" value="` + d.Target + `">
    <label for="username">Username</label>
    <input id="username" name="username" type="text" autocomplete="username" required autofocus>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <label for="totp">2FA Code</label>
    <input id="totp" name="totp" type="text" inputmode="numeric" autocomplete="one-time-code"
           placeholder="6-digit code · skip if not enrolled" maxlength="8">
    <button type="submit">Verify and continue</button>
  </form>`)
	if d.ErrorMsg != "" {
		b.WriteString(fmt.Sprintf("\n  <div class=\"error-banner\">%s</div>", d.ErrorMsg))
	}
	b.WriteString(`
  <p class="footnote">Clearance issues a signed cookie valid across all authorized sites (unified SSO).
     API clients authenticate via Bearer tokens and bypass this portal.</p>
</main>
</body>
</html>`)
	return b.String()
}
