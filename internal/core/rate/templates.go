package rate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// WaitingRoomAPIOverloadedResponse represents the structured JSON returned when machine/API routes encounter waiting room load shedding.
type WaitingRoomAPIOverloadedResponse struct {
	Error      string `json:"error"`
	RetryAfter int    `json:"retry_after"`
}

// WriteWaitingRoomOverloadedJSON writes an HTTP 465 JSON response with Retry-After header.
func WriteWaitingRoomOverloadedJSON(w http.ResponseWriter, retryAfter int) {
	if retryAfter <= 0 {
		retryAfter = 30
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(StatusWaitingRoom)

	resp := WaitingRoomAPIOverloadedResponse{
		Error:      "server_overloaded",
		RetryAfter: retryAfter,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// RenderWaitingRoomPage serves the self-contained, dark-mode virtual waiting room UI.
func RenderWaitingRoomPage(w http.ResponseWriter, queueID string, initialPos int, waitSeconds int, redirectURL string) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Retry-After", "10")

	// Set queue tracking cookie so reloads preserve queue position
	http.SetCookie(w, &http.Cookie{
		Name:     WaitingRoomQueueCookie,
		Value:    queueID,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
	})

	w.WriteHeader(StatusWaitingRoom)

	if redirectURL == "" {
		redirectURL = "/"
	}

	queueIDJSON, err := json.Marshal(queueID)
	if err != nil {
		queueIDJSON = []byte(`""`)
	}
	redirectURLJSON, err := json.Marshal(redirectURL)
	if err != nil {
		redirectURLJSON = []byte(`"/"`)
	}

	html := waitingRoomTemplate
	html = strings.ReplaceAll(html, "{{QUEUE_ID_JSON}}", string(queueIDJSON))
	html = strings.ReplaceAll(html, "{{INITIAL_POS}}", strconv.Itoa(initialPos))
	html = strings.ReplaceAll(html, "{{WAIT_SECONDS}}", strconv.Itoa(waitSeconds))
	html = strings.ReplaceAll(html, "{{REDIRECT_URL_JSON}}", string(redirectURLJSON))

	_, err = fmt.Fprint(w, html)
	return err
}

const waitingRoomTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Virtual Waiting Room — High Demand</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(17, 24, 39, 0.85);
      --card-border: rgba(255, 255, 255, 0.08);
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --accent: #3b82f6;
      --accent-glow: rgba(59, 130, 246, 0.4);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
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
      max-width: 480px;
      width: 100%;
      text-align: center;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6), 0 0 40px var(--accent-glow);
      backdrop-filter: blur(16px);
    }
    .icon {
      width: 64px;
      height: 64px;
      margin: 0 auto 1.5rem;
      border-radius: 50%;
      background: rgba(59, 130, 246, 0.12);
      border: 1px solid rgba(59, 130, 246, 0.25);
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--accent);
      animation: pulse 2.5s infinite ease-in-out;
    }
    @keyframes pulse {
      0%, 100% { transform: scale(1); box-shadow: 0 0 10px rgba(59, 130, 246, 0.2); }
      50% { transform: scale(1.06); box-shadow: 0 0 24px rgba(59, 130, 246, 0.5); }
    }
    h1 {
      font-size: 1.5rem;
      font-weight: 600;
      margin-bottom: 0.5rem;
      letter-spacing: -0.01em;
    }
    p {
      color: var(--text-muted);
      font-size: 0.9rem;
      line-height: 1.5;
      margin-bottom: 2rem;
    }
    .metrics {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .metric-box {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 1rem;
    }
    .metric-value {
      font-size: 1.75rem;
      font-weight: 700;
      color: #60a5fa;
      margin-bottom: 0.25rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    .metric-label {
      font-size: 0.75rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
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
      width: 5%;
      background: linear-gradient(90deg, #3b82f6, #60a5fa);
      border-radius: 999px;
      transition: width 0.3s ease;
    }
    .status {
      font-size: 0.8rem;
      color: var(--text-muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    .footer {
      margin-top: 2rem;
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
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"></circle>
        <polyline points="12 6 12 12 16 14"></polyline>
      </svg>
    </div>
    <h1>You are in the queue</h1>
    <p>We are experiencing exceptionally high traffic. Please keep this page open; you will be admitted automatically.</p>

    <div class="metrics">
      <div class="metric-box">
        <div id="position" class="metric-value">{{INITIAL_POS}}</div>
        <div class="metric-label">Queue Position</div>
      </div>
      <div class="metric-box">
        <div id="wait-time" class="metric-value">~{{WAIT_SECONDS}}s</div>
        <div class="metric-label">Estimated Wait</div>
      </div>
    </div>

    <div class="progress-bar-bg">
      <div id="progress" class="progress-bar-fill"></div>
    </div>
    <div id="status" class="status">Connected to live queue stream...</div>

    <div class="footer">Protected by Raiwall Gateway Surge Defense</div>
  </div>

  <script>
    (function() {
      const queueID = {{QUEUE_ID_JSON}};
      const redirectURL = {{REDIRECT_URL_JSON}};
      let initialPos = parseInt("{{INITIAL_POS}}", 10) || 1;

      const posEl = document.getElementById('position');
      const waitEl = document.getElementById('wait-time');
      const progressEl = document.getElementById('progress');
      const statusEl = document.getElementById('status');

      function setCookie(name, value, days) {
        let expires = "";
        if (days) {
          const date = new Date();
          date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
          expires = "; expires=" + date.toUTCString();
        }
        document.cookie = name + "=" + (value || "") + expires + "; path=/; SameSite=Lax; Secure";
      }

      function handleAdmitted(token) {
        if (token) {
          setCookie("rw_waiting_room_clearance", token, 1);
        }
        progressEl.style.width = '100%';
        posEl.textContent = "0";
        waitEl.textContent = "0s";
        statusEl.textContent = "Admitted! Redirecting...";
        setTimeout(function() {
          window.location.href = redirectURL;
        }, 500);
      }

      function connectSSE() {
        const url = "/.raiwall/waiting-room/events?id=" + encodeURIComponent(queueID);
        const evtSource = new EventSource(url);

        evtSource.addEventListener('update', function(e) {
          try {
            const data = JSON.parse(e.data);
            if (data.admitted) {
              evtSource.close();
              handleAdmitted(data.token);
              return;
            }
            posEl.textContent = data.position;
            waitEl.textContent = "~" + data.wait_seconds + "s";
            statusEl.textContent = "Advancing in queue...";
            if (initialPos > 0) {
              const pct = Math.max(5, Math.min(95, Math.round(((initialPos - data.position) / initialPos) * 100)));
              progressEl.style.width = pct + "%";
            }
          } catch(err) {}
        });

        evtSource.addEventListener('admitted', function(e) {
          evtSource.close();
          try {
            const data = JSON.parse(e.data);
            handleAdmitted(data.token);
          } catch(err) {
            handleAdmitted();
          }
        });

        evtSource.onerror = function() {
          statusEl.textContent = "Reconnecting to queue...";
        };
      }

      if (window.EventSource && queueID) {
        connectSSE();
      } else {
        statusEl.textContent = "Real-time updates unavailable. Refresh manually.";
      }
    })();
  </script>
</body>
</html>`
