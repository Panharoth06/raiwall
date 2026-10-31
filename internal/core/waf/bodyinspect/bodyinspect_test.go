package bodyinspect

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestDecode(t *testing.T) {
	plain := []byte("q=1' OR 1=1--")

	t.Run("gzip", func(t *testing.T) {
		got, err := Decode(gzipBytes(t, plain), "gzip", 4096)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("got (%q, %v)", got, err)
		}
	})

	t.Run("deflate", func(t *testing.T) {
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		_, _ = zw.Write(plain)
		_ = zw.Close()
		got, err := Decode(buf.Bytes(), "deflate", 4096)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("got (%q, %v)", got, err)
		}
	})

	t.Run("brotli", func(t *testing.T) {
		var buf bytes.Buffer
		bw := brotli.NewWriter(&buf)
		_, _ = bw.Write(plain)
		_ = bw.Close()
		got, err := Decode(buf.Bytes(), "br", 4096)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("got (%q, %v)", got, err)
		}
	})

	t.Run("bomb capped", func(t *testing.T) {
		got, err := Decode(gzipBytes(t, bytes.Repeat([]byte("A"), 1<<20)), "gzip", 1024)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1024 {
			t.Fatalf("decoded %d bytes, want cap 1024", len(got))
		}
	})

	t.Run("unsupported encoding keeps raw bytes", func(t *testing.T) {
		got, err := Decode(plain, "compress", 4096)
		if err == nil {
			t.Fatal("expected error")
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("raw bytes were not preserved: %q", got)
		}
	})

	t.Run("identity", func(t *testing.T) {
		got, err := Decode(plain, "identity", 4096)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("got (%q, %v)", got, err)
		}
	})
}

func gzipBytes(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}
