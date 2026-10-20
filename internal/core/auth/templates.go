package auth

import (
	"html"
	"io"
	"net/http"
)

// LoginTemplateData holds variables rendered into the login page.
type LoginTemplateData struct {
	TargetURL       string
	ErrorMessage    string
	ShowSimpleAuth  bool
	ShowOIDC        bool
	OIDCProviderName string
}

// RenderLoginPage streams the responsive zero-CDN dark-mode login UI to w.
func RenderLoginPage(w http.ResponseWriter, data LoginTemplateData) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.WriteHeader(http.StatusOK)

	_, err := io.WriteString(w, generateLoginPageHTML(data))
	return err
}

func generateLoginPageHTML(data LoginTemplateData) string {
	escapedTarget := html.EscapeString(data.TargetURL)
	escapedError := html.EscapeString(data.ErrorMessage)

	providerName := "SSO"
	if data.OIDCProviderName != "" {
		providerName = data.OIDCProviderName
	}

	errorBanner := ""
	if escapedError != "" {
		errorBanner = `
		<div class="error-banner">
			<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
				<circle cx="12" cy="12" r="10"></circle>
				<line x1="12" y1="8" x2="12" y2="12"></line>
				<line x1="12" y1="16" x2="12.01" y2="16"></line>
			</svg>
			<span>` + escapedError + `</span>
		</div>`
	}

	simpleForm := ""
	if data.ShowSimpleAuth {
		simpleForm = `
		<form method="POST" action="` + AuthLoginPath + `" class="auth-form">
			<input type="hidden" name="redirect" value="` + escapedTarget + `">
			<input type="hidden" name="auth_type" value="simple">
			
			<div class="form-group">
				<label for="username">Username</label>
				<input type="text" id="username" name="username" required autocomplete="username" placeholder="Enter username" autofocus>
			</div>

			<div class="form-group">
				<label for="password">Password</label>
				<input type="password" id="password" name="password" required autocomplete="current-password" placeholder="••••••••">
			</div>

			<button type="submit" class="btn btn-primary">Sign In</button>
		</form>`
	}

	oidcSection := ""
	if data.ShowOIDC {
		divider := ""
		if data.ShowSimpleAuth {
			divider = `<div class="divider"><span>OR</span></div>`
		}
		oidcSection = divider + `
		<form method="POST" action="` + AuthLoginPath + `" class="sso-form">
			<input type="hidden" name="redirect" value="` + escapedTarget + `">
			<input type="hidden" name="auth_type" value="oidc">
			<button type="submit" class="btn btn-sso">
				<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
					<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
				</svg>
				Sign In with ` + html.EscapeString(providerName) + `
			</button>
		</form>`
	}

	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Authentication Required | Raiwall Gateway</title>
	<style>
		:root {
			--bg-dark: #090d16;
			--card-bg: #111827;
			--card-border: #1f2937;
			--text-main: #f9fafb;
			--text-muted: #9ca3af;
			--primary: #3b82f6;
			--primary-hover: #2563eb;
			--error-bg: rgba(239, 68, 68, 0.15);
			--error-border: rgba(239, 68, 68, 0.4);
			--error-text: #fca5a5;
			--input-bg: #1f2937;
			--input-border: #374151;
		}
		* { box-sizing: border-box; margin: 0; padding: 0; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
			background-color: var(--bg-dark);
			color: var(--text-main);
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
			padding: 1.5rem;
		}
		.card {
			background-color: var(--card-bg);
			border: 1px solid var(--card-border);
			border-radius: 12px;
			width: 100%;
			max-width: 400px;
			padding: 2.25rem 2rem;
			box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5);
		}
		.header {
			text-align: center;
			margin-bottom: 2rem;
		}
		.logo {
			display: inline-flex;
			align-items: center;
			justify-content: center;
			width: 52px;
			height: 52px;
			background: linear-gradient(135deg, #1e3a8a, #3b82f6);
			border-radius: 12px;
			margin-bottom: 1rem;
			color: #ffffff;
			box-shadow: 0 0 15px rgba(59, 130, 246, 0.3);
		}
		h1 {
			font-size: 1.4rem;
			font-weight: 700;
			letter-spacing: -0.025em;
			margin-bottom: 0.35rem;
		}
		p.subtitle {
			font-size: 0.875rem;
			color: var(--text-muted);
		}
		.error-banner {
			display: flex;
			align-items: center;
			gap: 0.65rem;
			background: var(--error-bg);
			border: 1px solid var(--error-border);
			color: var(--error-text);
			padding: 0.75rem 1rem;
			border-radius: 8px;
			font-size: 0.875rem;
			margin-bottom: 1.5rem;
		}
		.auth-form {
			display: flex;
			flex-direction: column;
			gap: 1.15rem;
		}
		.form-group {
			display: flex;
			flex-direction: column;
			gap: 0.4rem;
		}
		label {
			font-size: 0.8125rem;
			font-weight: 500;
			color: var(--text-muted);
		}
		input[type="text"], input[type="password"] {
			background: var(--input-bg);
			border: 1px solid var(--input-border);
			color: var(--text-main);
			padding: 0.75rem 0.9rem;
			border-radius: 8px;
			font-size: 0.9375rem;
			outline: none;
			transition: border-color 0.15s ease, box-shadow 0.15s ease;
		}
		input[type="text"]:focus, input[type="password"]:focus {
			border-color: var(--primary);
			box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25);
		}
		.btn {
			display: inline-flex;
			align-items: center;
			justify-content: center;
			gap: 0.5rem;
			font-size: 0.9375rem;
			font-weight: 600;
			padding: 0.75rem 1rem;
			border-radius: 8px;
			border: none;
			cursor: pointer;
			transition: background-color 0.15s ease, transform 0.05s ease;
			width: 100%;
		}
		.btn:active { transform: scale(0.99); }
		.btn-primary {
			background-color: var(--primary);
			color: #ffffff;
			margin-top: 0.25rem;
		}
		.btn-primary:hover { background-color: var(--primary-hover); }
		.btn-sso {
			background-color: #1f2937;
			color: var(--text-main);
			border: 1px solid var(--card-border);
		}
		.btn-sso:hover { background-color: #374151; }
		.divider {
			display: flex;
			align-items: center;
			text-align: center;
			margin: 1.5rem 0;
			color: var(--text-muted);
			font-size: 0.75rem;
			font-weight: 600;
		}
		.divider::before, .divider::after {
			content: '';
			flex: 1;
			border-bottom: 1px solid var(--card-border);
		}
		.divider span { padding: 0 0.75rem; letter-spacing: 0.05em; }
		.footer {
			margin-top: 2rem;
			text-align: center;
			font-size: 0.75rem;
			color: #4b5563;
		}
	</style>
</head>
<body>
	<div class="card">
		<div class="header">
			<div class="logo">
				<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
					<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
				</svg>
			</div>
			<h1>Authentication Required</h1>
			<p class="subtitle">Protected by Raiwall Zero-Trust Gateway</p>
		</div>

		` + errorBanner + `
		` + simpleForm + `
		` + oidcSection + `

		<div class="footer">
			Raiwall Zero-Trust Security Gateway
		</div>
	</div>
</body>
</html>`
}
