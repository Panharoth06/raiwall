package caddy

import (
	"net/http"
	"testing"
)

func TestNormalizePayloadLocation(t *testing.T) {
	cases := map[string]string{
		"Query":      "QUERY",
		"Body":       "BODY",
		"Path":       "URLPATH",
		"Cookie":     "COOKIE",
		"User-Agent": "HEADER",
		"":           "",
	}
	for input, want := range cases {
		if got := normalizePayloadLocation(input); got != want {
			t.Errorf("normalizePayloadLocation(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCloneHeaderMapIsDeepCopy(t *testing.T) {
	src := http.Header{"Content-Type": {"application/json"}}
	cloned := cloneHeaderMap(src)

	if len(cloned) != 1 || cloned["Content-Type"][0] != "application/json" {
		t.Fatalf("unexpected clone: %+v", cloned)
	}

	cloned["Content-Type"][0] = "text/plain"
	if src.Get("Content-Type") != "application/json" {
		t.Errorf("clone mutated source header: %q", src.Get("Content-Type"))
	}
}
