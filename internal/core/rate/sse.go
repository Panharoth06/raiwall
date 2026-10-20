package rate

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// SSEUpdate represents the payload streamed to waiting room clients.
type SSEUpdate struct {
	Position    int    `json:"position"`
	WaitSeconds int    `json:"wait_seconds"`
	Admitted    bool   `json:"admitted"`
	Token       string `json:"token,omitempty"`
}

// WriteSSE formats and writes an event and JSON data according to the Server-Sent Events standard.
func WriteSSE(w io.Writer, event string, data any) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	var msg string
	if event != "" {
		msg = fmt.Sprintf("event: %s\ndata: %s\n\n", event, string(jsonData))
	} else {
		msg = fmt.Sprintf("data: %s\n\n", string(jsonData))
	}

	_, err = io.WriteString(w, msg)
	return err
}

// PrepareSSEHeaders configures standard non-buffering headers for SSE streaming.
func PrepareSSEHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
}
