package bot

// challengePageStyle is the theme-aware stylesheet for the HTTP 468 interstitial.
// It intentionally avoids gradients, glows, and blur so the page reads as a
// neutral security checkpoint rather than a branded marketing surface.
const challengePageStyle = `
    :root {
      --bg: #f8fafc;
      --fg: #0f172a;
      --muted: #526072;
      --border: #e2e8f0;
      --surface: #ffffff;
      --accent: #1d63d2;
      --success: #137a4b;
      --threat: #b42318;
      --focus: rgba(29, 99, 210, 0.3);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0b0f14;
        --fg: #e6edf3;
        --muted: #94a3b8;
        --border: #1e293b;
        --surface: #111820;
        --accent: #4cc2ff;
        --success: #3ddc97;
        --threat: #ff6b6b;
        --focus: rgba(76, 194, 255, 0.32);
      }
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    [hidden] { display: none !important; }
    html, body { height: 100%; }
    body {
      display: flex;
      flex-direction: column;
      min-height: 100dvh;
      background: var(--bg);
      color: var(--fg);
      font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      -webkit-font-smoothing: antialiased;
      text-rendering: optimizeLegibility;
    }
    .topbar {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 20px 24px;
    }
    .topbar svg { width: 22px; height: 22px; color: var(--accent); flex: none; }
    .brand { font-size: 14px; font-weight: 650; letter-spacing: -0.01em; }
    .brand-sub {
      padding-left: 8px;
      border-left: 1px solid var(--border);
      font-size: 14px;
      font-weight: 400;
      color: var(--muted);
    }
    main {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .stage { width: 100%; max-width: 380px; text-align: center; }
    .indicator {
      position: relative;
      width: 64px;
      height: 64px;
      margin: 0 auto 24px;
    }
    .ring {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      transform: rotate(-90deg);
      animation: spin 1.1s linear infinite;
    }
    .ring-track, .ring-arc { fill: none; stroke-width: 2; }
    .ring-track { stroke: var(--border); }
    .ring-arc { stroke: var(--accent); stroke-linecap: round; stroke-dasharray: 42 147; }
    .glyph {
      position: absolute;
      top: 50%;
      left: 50%;
      width: 26px;
      height: 26px;
      margin: -13px 0 0 -13px;
      opacity: 0;
      transition: opacity 0.12s linear;
    }
    body[data-state="checking"] .glyph-shield { opacity: 1; color: var(--accent); }
    body[data-state="done"] .ring { animation: none; }
    body[data-state="done"] .ring-arc,
    body[data-state="error"] .ring-arc { visibility: hidden; }
    body[data-state="done"] .ring-track { stroke: var(--success); }
    body[data-state="error"] .ring-track { stroke: var(--threat); }
    body[data-state="done"] .glyph-check { opacity: 1; color: var(--success); }
    body[data-state="error"] .glyph-cross { opacity: 1; color: var(--threat); }
    @keyframes spin { to { transform: rotate(270deg); } }
    h1 {
      font-size: 20px;
      line-height: 1.3;
      font-weight: 650;
      letter-spacing: -0.01em;
    }
    .message {
      margin-top: 8px;
      color: var(--muted);
      font-size: 14px;
      line-height: 1.6;
      text-wrap: pretty;
    }
    .meter {
      height: 2px;
      max-width: 220px;
      margin: 24px auto 0;
      border-radius: 2px;
      background: var(--border);
      overflow: hidden;
    }
    .meter-fill {
      height: 100%;
      width: 100%;
      background: var(--accent);
      transform: scaleX(0);
      transform-origin: left center;
      transition: transform 0.15s linear;
    }
    body[data-state="done"] .meter-fill { background: var(--success); }
    .destination {
      margin-top: 16px;
      color: var(--muted);
      font-size: 14px;
      line-height: 1.6;
      display: -webkit-box;
      -webkit-line-clamp: 2;
      -webkit-box-orient: vertical;
      overflow: hidden;
      overflow-wrap: anywhere;
    }
    .destination code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 14px;
      color: var(--fg);
    }
    .retry {
      margin-top: 24px;
      height: 36px;
      padding: 0 16px;
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--surface);
      color: var(--fg);
      font: inherit;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: background-color 0.15s ease-out, border-color 0.15s ease-out;
    }
    .retry:hover { border-color: var(--muted); background: var(--bg); }
    .retry:active { background: var(--surface); }
    .retry:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .footnote { margin-top: 12px; color: var(--muted); font-size: 14px; line-height: 1.6; }
    footer {
      padding: 20px 24px calc(20px + env(safe-area-inset-bottom));
      text-align: center;
      color: var(--muted);
      font-size: 14px;
    }
    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border: 0;
    }
    @media (prefers-reduced-motion: reduce) {
      .ring { animation: none; }
      .glyph, .meter-fill, .retry { transition: none; }
    }
    @media (max-width: 420px) {
      .brand-sub { display: none; }
      .topbar { padding: 16px; }
      main { padding: 16px; }
    }
`
