package waf

import (
	"net/http"
	"testing"
)

func TestScanSSRF(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
		level DetectionLevel
	}{
		{"aws metadata", "url=http://169.254.169.254/latest/meta-data/", true, LevelStrong},
		{"gcp metadata", "target=http://metadata.google.internal/computeMetadata/v1/", true, LevelStrong},
		{"alibaba metadata", "u=http://100.100.100.200/latest/meta-data/", true, LevelStrong},
		{"weak loopback", "redirect=http://127.0.0.1:3000/callback", true, LevelWeak},
		{"weak rfc1918", "fetch=https://10.1.2.3/admin", true, LevelWeak},
		{"weak same prefix after userinfo", "u=http://admin@192.168.1.10/", true, LevelWeak},
		{"benign public url", "next=https://example.com/docs", false, 0},
		{"benign text", "note starts with dots .: and @ but no url", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := scanSSRF(tc.value)
			if !tc.want {
				if found {
					t.Errorf("unexpected detection: %+v", got)
				}
				return
			}
			requireDetection(t, got, found, ModuleSSRF, tc.level, tc.name)
		})
	}
}

func TestScanFileUpload(t *testing.T) {
	cases := []struct {
		name      string
		paramName string
		value     string
		want      bool
		level     DetectionLevel
	}{
		{"php upload", "attachment.filename", "shell.php", true, LevelStrong},
		{"jsp upload", "attachment.filename", "C:\\fakepath\\payload.jspx", true, LevelStrong},
		{"double extension", "attachment.filename", "shell.php.jpg", true, LevelStrong},
		{"weak tooling upload", "attachment.filename", "job.py", true, LevelWeak},
		{"benign image", "attachment.filename", "photo.png", false, 0},
		{"benign source file", "attachment.filename", "report.source", false, 0},
		{"form field not gated", "comment", "shell.php", false, 0},
		{"empty value", "attachment.filename", "", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := scanFileUpload(tc.paramName, tc.value)
			if !tc.want {
				if found {
					t.Errorf("unexpected detection: %+v", got)
				}
				return
			}
			requireDetection(t, got, found, ModuleFileUpload, tc.level, tc.name)
		})
	}
}

func TestScanMalHTTP(t *testing.T) {
	t.Run("DuplicateContentLengthStrong", func(t *testing.T) {
		h := http.Header{"Content-Length": []string{"10", "20"}}
		got, found := scanMalHTTP(h)
		requireDetection(t, got, found, ModuleMalHTTP, LevelStrong, "dup CL")
	})

	t.Run("ContentLengthPlusTransferEncodingStrong", func(t *testing.T) {
		h := http.Header{"Content-Length": []string{"10"}, "Transfer-Encoding": []string{"chunked"}}
		got, found := scanMalHTTP(h)
		requireDetection(t, got, found, ModuleMalHTTP, LevelStrong, "CL+TE")
	})

	t.Run("ConflictingTransferEncodingStrong", func(t *testing.T) {
		h := http.Header{"Transfer-Encoding": []string{"chunked", "identity"}}
		got, found := scanMalHTTP(h)
		requireDetection(t, got, found, ModuleMalHTTP, LevelStrong, "conflict TE")
	})

	t.Run("DuplicateSameTransferEncodingWeak", func(t *testing.T) {
		h := http.Header{"Transfer-Encoding": []string{"chunked", "chunked"}}
		got, found := scanMalHTTP(h)
		requireDetection(t, got, found, ModuleMalHTTP, LevelWeak, "dup TE")
	})

	t.Run("ObfuscatedTransferEncodingWeak", func(t *testing.T) {
		h := http.Header{"Transfer-Encoding": []string{"chunkus"}}
		got, found := scanMalHTTP(h)
		requireDetection(t, got, found, ModuleMalHTTP, LevelWeak, "obf TE")
	})

	t.Run("BenignHeaders", func(t *testing.T) {
		h := http.Header{"Content-Length": []string{"10"}, "Content-Type": []string{"application/json"}}
		if _, found := scanMalHTTP(h); found {
			t.Error("unexpected detection for benign headers")
		}
	})

	t.Run("NilHeaders", func(t *testing.T) {
		if _, found := scanMalHTTP(nil); found {
			t.Error("unexpected detection for nil headers")
		}
	})
}

func TestDetectCSRF(t *testing.T) {
	t.Run("CrossOriginStrong", func(t *testing.T) {
		h := http.Header{"Origin": []string{"https://attacker.example"}}
		got, found := detectCSRF(http.MethodPost, h, "shop.example")
		requireDetection(t, got, found, ModuleCSRF, LevelStrong, "cross origin")
	})

	t.Run("SameOriginNoDetection", func(t *testing.T) {
		h := http.Header{"Origin": []string{"https://shop.example"}}
		if _, found := detectCSRF(http.MethodPost, h, "shop.example"); found {
			t.Error("unexpected detection for same-origin request")
		}
	})

	t.Run("DefaultPortNormalization", func(t *testing.T) {
		h := http.Header{"Origin": []string{"https://shop.example:443"}}
		if _, found := detectCSRF(http.MethodPost, h, "shop.example"); found {
			t.Error("default-port origin should compare equal")
		}
	})

	t.Run("NullOriginWeak", func(t *testing.T) {
		h := http.Header{"Origin": []string{"null"}}
		got, found := detectCSRF(http.MethodPost, h, "shop.example")
		requireDetection(t, got, found, ModuleCSRF, LevelWeak, "null origin")
	})

	t.Run("MalformedOriginWeak", func(t *testing.T) {
		h := http.Header{"Origin": []string{"not a url"}}
		got, found := detectCSRF(http.MethodPost, h, "shop.example")
		requireDetection(t, got, found, ModuleCSRF, LevelWeak, "bad origin")
	})

	t.Run("RefererMismatchWeak", func(t *testing.T) {
		h := http.Header{"Referer": []string{"https://other.example/form"}}
		got, found := detectCSRF(http.MethodPost, h, "shop.example")
		requireDetection(t, got, found, ModuleCSRF, LevelWeak, "referer")
	})

	t.Run("SafeMethodsIgnored", func(t *testing.T) {
		h := http.Header{"Origin": []string{"https://attacker.example"}}
		if _, found := detectCSRF(http.MethodGet, h, "shop.example"); found {
			t.Error("safe methods must not trigger CSRF detection")
		}
	})
}
