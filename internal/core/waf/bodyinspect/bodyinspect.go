// Package bodyinspect prepares request bodies for WAF inspection without
// touching the bytes forwarded upstream.
package bodyinspect

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

// MaxDecodedSize caps the bytes produced by decompression for inspection. A
// compression bomb cannot grow memory beyond this bound because only the
// inspection copy is decoded.
const MaxDecodedSize = 1024 * 1024

// Decode decompresses an inspection copy of a body according to its
// Content-Encoding. Unsupported encodings return the original bytes together
// with an error so callers can still scan the raw payload.
func Decode(body []byte, contentEncoding string, limit int64) ([]byte, error) {
	if len(body) == 0 || strings.TrimSpace(contentEncoding) == "" {
		return body, nil
	}
	if limit <= 0 {
		limit = MaxDecodedSize
	}

	encodings := strings.Split(strings.ToLower(contentEncoding), ",")
	// Content-Encoding lists transformations in application order; decode in
	// reverse so the innermost encoding is removed first.
	for i := len(encodings) - 1; i >= 0; i-- {
		enc := strings.TrimSpace(encodings[i])
		switch enc {
		case "", "identity":
			continue
		case "gzip", "x-gzip":
			zr, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				return body, err
			}
			decoded, err := readLimited(zr, limit)
			_ = zr.Close()
			if err != nil {
				return body, err
			}
			body = decoded
		case "deflate":
			zr, err := zlib.NewReader(bytes.NewReader(body))
			if err != nil {
				return body, err
			}
			decoded, err := readLimited(zr, limit)
			_ = zr.Close()
			if err != nil {
				return body, err
			}
			body = decoded
		case "br":
			decoded, err := readLimited(brotli.NewReader(bytes.NewReader(body)), limit)
			if err != nil {
				return body, err
			}
			body = decoded
		default:
			return body, fmt.Errorf("unsupported content-encoding %q", enc)
		}
	}
	return body, nil
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, limit))
}
