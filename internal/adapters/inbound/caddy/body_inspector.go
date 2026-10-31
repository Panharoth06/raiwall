package caddy

import (
	"bytes"
	"io"
	"net/http"
)

// readInspectableBody returns up to limit bytes of the request body and
// reconstructs r.Body with those bytes followed by the unread remainder.
//
// Bodies larger than limit are inspected by bounded prefix instead of being
// skipped entirely, and the returned slice never aliases a pooled buffer (the
// previous chunked-oversize path returned a buffer to the pool while still
// reading from it, corrupting in-flight requests). The returned slice may share
// storage with the reconstructed body, so callers must treat it as read-only.
func readInspectableBody(r *http.Request, limit int64) ([]byte, error) {
	if r == nil || r.Body == nil || r.ContentLength == 0 || limit <= 0 {
		return nil, nil
	}

	if r.ContentLength > 0 && r.ContentLength <= limit {
		body := make([]byte, r.ContentLength)
		_, err := io.ReadFull(r.Body, body)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err != nil {
			return body, err
		}
		return body, nil
	}

	// Unknown length or larger than the inspection limit: read a bounded
	// prefix and stream the rest through a reconstructed body.
	prefix := make([]byte, limit)
	n, err := io.ReadFull(r.Body, prefix)
	prefix = prefix[:n]
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), r.Body))

	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return prefix, err
	}
	return prefix, nil
}
