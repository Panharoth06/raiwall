package caddy

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReadInspectableBody_SmallBody(t *testing.T) {
	body := []byte(`{"q":"hello"}`)
	r := &http.Request{Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}

	got, err := readInspectableBody(r, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("inspected %q, want %q", got, body)
	}
	assertBodyEquals(t, r, body)
}

func TestReadInspectableBody_OversizedIsInspectedByPrefix(t *testing.T) {
	payload := []byte("AAAAAAA' OR 1=1--")
	r := &http.Request{Body: io.NopCloser(bytes.NewReader(payload)), ContentLength: int64(len(payload))}

	got, err := readInspectableBody(r, 8)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "AAAAAAA'" {
		t.Fatalf("inspected %q, want first 8 bytes", got)
	}
	// The full body must still reach the upstream, byte for byte.
	assertBodyEquals(t, r, payload)
}

func TestReadInspectableBody_ChunkedOversizedKeepsFullBody(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 2048)
	r := &http.Request{Body: io.NopCloser(bytes.NewReader(payload)), ContentLength: -1}

	got, err := readInspectableBody(r, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1024 {
		t.Fatalf("inspected %d bytes, want 1024", len(got))
	}
	assertBodyEquals(t, r, payload)
}

func TestReadInspectableBody_EmptyBody(t *testing.T) {
	r := &http.Request{Body: io.NopCloser(bytes.NewReader(nil)), ContentLength: 0}
	got, err := readInspectableBody(r, 1024)
	if err != nil || got != nil {
		t.Fatalf("got (%q, %v), want (nil, nil)", got, err)
	}
}

func TestReadInspectableBody_ReconstructsFullBody(t *testing.T) {
	// Regression guard for the pooled-buffer use-after-return: the prefix is
	// request-local (never pooled) and the forwarded body stays byte-identical.
	payload := []byte(strings.Repeat("ab", 2048))
	r := &http.Request{Body: io.NopCloser(bytes.NewReader(payload)), ContentLength: -1}
	if _, err := readInspectableBody(r, 64); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBodyEquals(t, r, payload)
}

func assertBodyEquals(t *testing.T, r *http.Request, want []byte) {
	t.Helper()
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read reconstructed body: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("reconstructed body = %q (len %d), want %q (len %d)",
			truncateForLog(got), len(got), truncateForLog(want), len(want))
	}
}

func truncateForLog(b []byte) string {
	const max = 64
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}
