package bot

// HTTPStatusChallenge is HTTP 468 used for stateless Proof-of-Work browser challenges.
const HTTPStatusChallenge = 468

// challengeHTMLTemplate is the self-contained, responsive, dark-mode HTTP 468 challenge page
// with an inline vanilla JS WebCrypto SHA-256 solver. It requires zero external scripts or CDNs.
const challengeHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow, noarchive">
  <title>Security Check | Raiwall</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(17, 24, 39, 0.8);
      --card-border: rgba(255, 255, 255, 0.1);
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --primary: #3b82f6;
      --accent: #60a5fa;
      --glow: rgba(59, 130, 246, 0.25);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 2.5rem;
      max-width: 440px;
      width: 100%;
      text-align: center;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4), 0 0 40px var(--glow);
      backdrop-filter: blur(12px);
    }
    .icon {
      width: 56px;
      height: 56px;
      margin: 0 auto 1.5rem;
      border-radius: 50%;
      background: rgba(59, 130, 246, 0.15);
      border: 1px solid rgba(59, 130, 246, 0.3);
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--accent);
      animation: pulse 2s infinite ease-in-out;
    }
    @keyframes pulse {
      0%, 100% { transform: scale(1); box-shadow: 0 0 10px rgba(59, 130, 246, 0.3); }
      50% { transform: scale(1.05); box-shadow: 0 0 20px rgba(59, 130, 246, 0.6); }
    }
    h1 {
      font-size: 1.35rem;
      font-weight: 600;
      margin-bottom: 0.5rem;
      letter-spacing: -0.01em;
    }
    p {
      color: var(--text-muted);
      font-size: 0.875rem;
      line-height: 1.5;
      margin-bottom: 1.5rem;
    }
    .progress-bar-bg {
      width: 100%;
      height: 6px;
      background: rgba(255, 255, 255, 0.08);
      border-radius: 999px;
      overflow: hidden;
      margin-bottom: 1rem;
    }
    .progress-bar-fill {
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, #3b82f6, #60a5fa);
      border-radius: 999px;
      transition: width 0.15s ease;
    }
    .status {
      font-size: 0.75rem;
      color: var(--text-muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    .footer {
      margin-top: 1.5rem;
      padding-top: 1rem;
      border-top: 1px solid var(--card-border);
      font-size: 0.75rem;
      color: #6b7280;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    </div>
    <h1>Verifying Connection</h1>
    <p>Please wait a moment while we verify your browser security integrity.</p>
    <div class="progress-bar-bg">
      <div id="progress" class="progress-bar-fill"></div>
    </div>
    <div id="status" class="status">Initializing verification...</div>
    <div class="footer">Protected by Raiwall Gateway Defense</div>
  </div>

  <script>
    (function() {
      const challenge = {{.ChallengeJSON}};
      const redirectURL = {{.RedirectURL}};
      const progressBar = document.getElementById('progress');
      const statusText = document.getElementById('status');

      function hex(buffer) {
        const bytes = new Uint8Array(buffer);
        let s = '';
        for (let i = 0; i < bytes.length; i++) {
          s += bytes[i].toString(16).padStart(2, '0');
        }
        return s;
      }

      async function solve() {
        if (!window.crypto || !window.crypto.subtle) {
          statusText.textContent = "WebCrypto required. Please use a modern browser.";
          return;
        }

        const encoder = new TextEncoder();
        const max = challenge.maxNumber || 50000;
        const salt = challenge.salt || '';
        const target = challenge.challenge || '';
        const batchSize = 1000;
        let num = 0;

        statusText.textContent = "Validating computational proof...";

        function runBatch() {
          const limit = Math.min(num + batchSize, max);
          const promises = [];

          for (let i = num; i < limit; i++) {
            const data = encoder.encode(salt + i);
            promises.push(
              window.crypto.subtle.digest('SHA-256', data).then(buf => {
                if (hex(buf) === target) return i;
                return null;
              })
            );
          }

          Promise.all(promises).then(results => {
            const found = results.find(v => v !== null);
            if (found !== undefined) {
              progressBar.style.width = '100%';
              statusText.textContent = "Proof accepted. Redirecting...";
              submitSolution({
                algorithm: challenge.algorithm,
                challenge: challenge.challenge,
                number: found,
                salt: challenge.salt,
                signature: challenge.signature
              });
              return;
            }

            num = limit;
            const progress = Math.min(Math.round((num / max) * 100), 98);
            progressBar.style.width = progress + '%';

            if (num < max) {
              setTimeout(runBatch, 0);
            } else {
              statusText.textContent = "Verification timeout. Please refresh.";
            }
          }).catch(err => {
            statusText.textContent = "Verification error: " + err.message;
          });
        }

        runBatch();
      }

      function submitSolution(payload) {
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/.raiwall/challenge/verify';

        const payloadInput = document.createElement('input');
        payloadInput.type = 'hidden';
        payloadInput.name = 'payload';
        payloadInput.value = JSON.stringify(payload);
        form.appendChild(payloadInput);

        const redirectInput = document.createElement('input');
        redirectInput.type = 'hidden';
        redirectInput.name = 'redirect';
        redirectInput.value = redirectURL;
        form.appendChild(redirectInput);

        document.body.appendChild(form);
        form.submit();
      }

      window.addEventListener('DOMContentLoaded', solve);
    })();
  </script>
</body>
</html>`
