package normalizer

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
)

func TestExtractParameters_PathAndQuery(t *testing.T) {
	path := "/users/profile"
	query := "id=123&sort=desc&search=test+query"
	headers := http.Header{}
	headers.Set("X-Custom-Header", "admin-value")
	headers.Set("Cookie", "session_id=abc123xyz; role=operator")

	params := ExtractParameters(path, query, headers, nil)

	hasParam := func(name, val string, loc Location) bool {
		for _, p := range params {
			if p.Name == name && p.Value == val && p.Location == loc {
				return true
			}
		}
		return false
	}

	if !hasParam("path", "/users/profile", LocationPath) {
		t.Errorf("expected path parameter")
	}
	if !hasParam("id", "123", LocationQuery) {
		t.Errorf("expected query param id=123")
	}
	if !hasParam("sort", "desc", LocationQuery) {
		t.Errorf("expected query param sort=desc")
	}
	if !hasParam("session_id", "abc123xyz", LocationCookie) {
		t.Errorf("expected cookie param session_id=abc123xyz")
	}
	if !hasParam("role", "operator", LocationCookie) {
		t.Errorf("expected cookie param role=operator")
	}
	if !hasParam("X-Custom-Header", "admin-value", LocationHeader) {
		t.Errorf("expected X-Custom-Header parameter")
	}
}

func TestExtractParameters_JSONBody(t *testing.T) {
	jsonPayload := []byte(`{
		"username": "alice",
		"details": {
			"role": "admin",
			"tags": ["web", "waf"]
		},
		"active": true,
		"count": 42
	}`)

	headers := http.Header{}
	headers.Set("Content-Type", "application/json")

	params := ExtractParameters("/api/user", "", headers, jsonPayload)

	expected := map[string]string{
		"username":        "alice",
		"details.role":    "admin",
		"details.tags[0]": "web",
		"details.tags[1]": "waf",
		"active":          "true",
		"count":           "42",
	}

	for k, v := range expected {
		found := false
		for _, p := range params {
			if p.Name == k && p.Value == v && p.Location == LocationJSON {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected JSON param %s=%s, not found in %#v", k, v, params)
		}
	}
}

func TestExtractParameters_URLEncodedForm(t *testing.T) {
	formData := []byte("field1=value1&field2=1%27+OR+%271%27%3D%271")
	headers := http.Header{}
	headers.Set("Content-Type", "application/x-www-form-urlencoded")

	params := ExtractParameters("/login", "", headers, formData)

	foundField2 := false
	for _, p := range params {
		if p.Name == "field2" && p.Location == LocationBody {
			foundField2 = true
			if !strings.Contains(p.Value, "OR") {
				t.Errorf("expected field2 to contain decoded OR, got %q", p.Value)
			}
		}
	}
	if !foundField2 {
		t.Errorf("expected field2 parameter in body")
	}
}

func TestExtractParameters_MultipartForm(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	// Normal text field
	_ = writer.WriteField("title", "My Vulnerability Report")
	_ = writer.WriteField("author", "security_researcher")

	// Text file attachment
	part, _ := writer.CreateFormFile("attachment", "notes.txt")
	_, _ = part.Write([]byte("Confidential security analysis notes"))

	// Large binary file > 1MB: ensure its content is skipped
	largePart, _ := writer.CreateFormFile("large_archive", "backup.tar.gz")
	largeData := bytes.Repeat([]byte{0x00, 0xFF, 0x12, 0x34}, (1024*1024+10)/4)
	_, _ = largePart.Write(largeData)

	_ = writer.Close()

	headers := http.Header{}
	headers.Set("Content-Type", writer.FormDataContentType())

	params := ExtractParameters("/upload", "", headers, body.Bytes())

	hasParam := func(name, val string) bool {
		for _, p := range params {
			if p.Name == name && strings.Contains(p.Value, val) && p.Location == LocationMultipart {
				return true
			}
		}
		return false
	}

	if !hasParam("title", "My Vulnerability Report") {
		t.Errorf("missing multipart field 'title'")
	}
	if !hasParam("attachment.filename", "notes.txt") {
		t.Errorf("missing multipart filename 'notes.txt'")
	}
	if !hasParam("attachment.content", "Confidential security analysis") {
		t.Errorf("missing multipart content for small text file")
	}
	if !hasParam("large_archive.filename", "backup.tar.gz") {
		t.Errorf("missing multipart filename for large file")
	}
	// Content of large file (>1MB) must NOT be extracted
	if hasParam("large_archive.content", "") {
		t.Errorf("large binary file content should NOT have been extracted")
	}
}
