package bot

// challengeHTMLTemplate is the self-contained, zero-dependency HTTP 468 interstitial.
//
// Flow (modeled on SafeLine's anti-bot UX):
//  1. Passive browser capability check runs immediately; no user interaction.
//  2. A stateless SHA-256 proof-of-work is solved quietly in the background.
//  3. On success the page shows a confirmation state, then returns the visitor
//     to the originally requested URL automatically.
//  4. On timeout or an unsupported browser it renders an actionable error state
//     with a single retry action instead of leaving the visitor stuck.
//
// It ships light and dark themes, honors prefers-reduced-motion, and requires
// no external scripts, fonts, or CDNs.
const challengeHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="robots" content="noindex, nofollow, noarchive">
  <meta name="color-scheme" content="light dark">
  <title>Security Check - Raiwall</title>
  <noscript><style>.js-only { display: none !important; }</style></noscript>
  <style>` + challengePageStyle + `</style>
</head>
<body data-state="checking">
  <header class="topbar">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
    <span class="brand">Raiwall</span>
    <span class="brand-sub">Gateway Defense</span>
  </header>

  <main>
    <div class="stage js-only">
      <div class="indicator" aria-hidden="true">
        <svg class="ring" viewBox="0 0 64 64">
          <circle class="ring-track" cx="32" cy="32" r="30"/>
          <circle class="ring-arc" cx="32" cy="32" r="30"/>
        </svg>
        <svg class="glyph glyph-shield" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <svg class="glyph glyph-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M4.5 12.5l5 5L19.5 7"/>
        </svg>
        <svg class="glyph glyph-cross" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M6 6l12 12M18 6L6 18"/>
        </svg>
      </div>

      <h1 id="title">Checking your browser</h1>
      <p id="message" class="message">Confirming this connection is a real browser. This takes a few seconds.</p>

      <div id="meter" class="meter" role="progressbar" aria-labelledby="title" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
        <div id="progress" class="meter-fill"></div>
      </div>

      <p id="destination" class="destination" hidden>Returning to <code>{{.RedirectURL}}</code></p>
      <button id="retry" class="retry" type="button" hidden>Retry verification</button>
      <p id="hint" class="footnote" hidden>If this keeps happening, contact the site administrator.</p>
    </div>

    <noscript>
      <div class="stage">
        <h1>JavaScript required</h1>
        <p class="message">Enable JavaScript to complete the browser security check, then reload this page.</p>
      </div>
    </noscript>
  </main>

  <footer>Protected by Raiwall Gateway Defense</footer>

  <p id="announcer" class="sr-only" role="status" aria-live="polite"></p>

  <script>` + challengePageScript + `</script>
</body>
</html>`
