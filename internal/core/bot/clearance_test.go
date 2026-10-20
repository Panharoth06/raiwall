package bot

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/altcha-org/altcha-lib-go"
)

func TestClearanceTokenLifecycle(t *testing.T) {
	secret := "test-secret-clearance-456"
	cm := NewClearanceManager(ClearanceConfig{
		Secret: secret,
		TTL:    1 * time.Hour,
	}, nil)

	ip := net.ParseIP("192.168.1.50")
	ja4 := "t13d1516h2_chrome_browser_hash"

	// 1. Valid token
	expires := time.Now().Add(1 * time.Hour)
	token := cm.GenerateToken(ip, ja4, expires)
	if !cm.ValidateToken(token, ip, ja4) {
		t.Fatalf("ValidateToken() failed for valid token")
	}

	// 2. IP mismatch
	otherIP := net.ParseIP("192.168.1.99")
	if cm.ValidateToken(token, otherIP, ja4) {
		t.Errorf("ValidateToken() succeeded with mismatched IP")
	}

	// 3. JA4 mismatch
	otherJA4 := "t13d1516h2_python_hash"
	if cm.ValidateToken(token, ip, otherJA4) {
		t.Errorf("ValidateToken() succeeded with mismatched JA4")
	}

	// 4. Expired token
	pastExpires := time.Now().Add(-10 * time.Minute)
	expiredToken := cm.GenerateToken(ip, ja4, pastExpires)
	if cm.ValidateToken(expiredToken, ip, ja4) {
		t.Errorf("ValidateToken() succeeded for expired token")
	}

	// 5. Tampered signature
	parts := strings.Split(token, ".")
	tamperedToken := parts[0] + ".bad000"
	if cm.ValidateToken(tamperedToken, ip, ja4) {
		t.Errorf("ValidateToken() succeeded for tampered signature")
	}

	// 6. Malformed tokens
	if cm.ValidateToken("not-a-token", ip, ja4) {
		t.Errorf("ValidateToken() succeeded for malformed token")
	}
	if cm.ValidateToken("", ip, ja4) {
		t.Errorf("ValidateToken() succeeded for empty token")
	}
}

func TestClearanceManager_ValidateRequest(t *testing.T) {
	cm := NewClearanceManager(ClearanceConfig{
		Secret: "test-secret",
		TTL:    1 * time.Hour,
	}, nil)

	ip := net.ParseIP("10.0.0.1")
	ja4 := "t13d1516h2_test"

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	if cm.ValidateRequest(req, ip, ja4) {
		t.Errorf("ValidateRequest() should fail with no cookie")
	}

	token := cm.GenerateToken(ip, ja4, time.Now().Add(1*time.Hour))
	req.AddCookie(&http.Cookie{
		Name:  ClearanceCookieName,
		Value: token,
	})

	if !cm.ValidateRequest(req, ip, ja4) {
		t.Errorf("ValidateRequest() failed with valid cookie")
	}
}

func TestClearanceManager_HandleChallengeVerify(t *testing.T) {
	secret := "pow-verify-secret"
	pow := NewPoWEngine(PoWConfig{
		Secret:     secret,
		Difficulty: 500,
	})
	cm := NewClearanceManager(ClearanceConfig{
		Secret: secret,
		TTL:    2 * time.Hour,
	}, pow)

	ip := net.ParseIP("203.0.113.10")
	ja4 := "t13d1516h2_browser"

	// 1. Create and solve a challenge
	challenge, err := pow.CreateChallenge()
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}
	solution, err := altcha.SolveChallenge(challenge.Challenge, challenge.Salt, altcha.SHA256, int(challenge.MaxNumber), 0, nil)
	if err != nil {
		t.Fatalf("SolveChallenge failed: %v", err)
	}

	payloadStruct := altcha.Payload{
		Algorithm: challenge.Algorithm,
		Challenge: challenge.Challenge,
		Number:    int64(solution.Number),
		Salt:      challenge.Salt,
		Signature: challenge.Signature,
	}
	payloadBytes, _ := json.Marshal(payloadStruct)

	// 2. Test form POST verification (standard browser flow)
	form := url.Values{}
	form.Set("payload", string(payloadBytes))
	form.Set("redirect", "/protected/page")

	req := httptest.NewRequest(http.MethodPost, ChallengeVerifyPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	cm.HandleChallengeVerify(rec, req, ip, ja4)

	res := rec.Result()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("StatusCode = %d, want %d (303)", res.StatusCode, http.StatusSeeOther)
	}
	if loc := res.Header.Get("Location"); loc != "/protected/page" {
		t.Errorf("Location = %q, want /protected/page", loc)
	}

	cookies := res.Cookies()
	var clearanceCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == ClearanceCookieName {
			clearanceCookie = c
			break
		}
	}
	if clearanceCookie == nil {
		t.Fatalf("Expected rw_clearance cookie to be set")
	}
	if !clearanceCookie.HttpOnly {
		t.Errorf("Expected HttpOnly cookie")
	}
	if !cm.ValidateToken(clearanceCookie.Value, ip, ja4) {
		t.Errorf("Issued cookie token is invalid for client IP and JA4")
	}

	// 3. Test open redirect prevention (with fresh challenge solution)
	ch2, _ := pow.CreateChallenge()
	sol2, _ := altcha.SolveChallenge(ch2.Challenge, ch2.Salt, altcha.SHA256, int(ch2.MaxNumber), 0, nil)
	p2 := altcha.Payload{
		Algorithm: ch2.Algorithm,
		Challenge: ch2.Challenge,
		Number:    int64(sol2.Number),
		Salt:      ch2.Salt,
		Signature: ch2.Signature,
	}
	p2Bytes, _ := json.Marshal(p2)

	form2 := url.Values{}
	form2.Set("payload", string(p2Bytes))
	form2.Set("redirect", "//evil.com/phish")
	req2 := httptest.NewRequest(http.MethodPost, ChallengeVerifyPath, strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()

	cm.HandleChallengeVerify(rec2, req2, ip, ja4)
	res2 := rec2.Result()
	if loc := res2.Header.Get("Location"); loc != "/" {
		t.Errorf("Open redirect sanitization failed: got %q, want /", loc)
	}

	// 4. Test invalid solution rejection
	badForm := url.Values{}
	badForm.Set("payload", "invalid-payload-string")
	req3 := httptest.NewRequest(http.MethodPost, ChallengeVerifyPath, strings.NewReader(badForm.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec3 := httptest.NewRecorder()

	cm.HandleChallengeVerify(rec3, req3, ip, ja4)
	res3 := rec3.Result()
	if res3.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for invalid solution, got %d", res3.StatusCode)
	}

	// 5. Test JSON submission mode
	// Solve fresh challenge because previous solution was redeemed
	freshCh, _ := pow.CreateChallenge()
	freshSol, _ := altcha.SolveChallenge(freshCh.Challenge, freshCh.Salt, altcha.SHA256, int(freshCh.MaxNumber), 0, nil)
	freshPayloadStruct := altcha.Payload{
		Algorithm: freshCh.Algorithm,
		Challenge: freshCh.Challenge,
		Number:    int64(freshSol.Number),
		Salt:      freshCh.Salt,
		Signature: freshCh.Signature,
	}

	jsonBody, _ := json.Marshal(map[string]interface{}{
		"payload":  freshPayloadStruct,
		"redirect": "/app/welcome",
	})
	req4 := httptest.NewRequest(http.MethodPost, ChallengeVerifyPath, bytes.NewReader(jsonBody))
	req4.Header.Set("Content-Type", "application/json")
	req4.Header.Set("Accept", "application/json")
	rec4 := httptest.NewRecorder()

	cm.HandleChallengeVerify(rec4, req4, ip, ja4)
	res4 := rec4.Result()
	if res4.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK for JSON verify, got %d", res4.StatusCode)
	}

	// 6. Test Method Not Allowed for GET / HEAD
	getReq := httptest.NewRequest(http.MethodGet, ChallengeVerifyPath, nil)
	getRec := httptest.NewRecorder()
	cm.HandleChallengeVerify(getRec, getReq, ip, ja4)
	if getRec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 Method Not Allowed for GET, got %d", getRec.Code)
	}
}

func TestSanitizeRedirect(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/valid/path", "/valid/path"},
		{"/valid?foo=bar#hash", "/valid?foo=bar#hash"},
		{"", "/"},
		{"   ", "/"},
		{"https://evil.com/phish", "/"},
		{"http://evil.com", "/"},
		{"//evil.com", "/"},
		{"///evil.com", "/"},
		{"/\\evil.com", "/"},
		{"/path\r\nSet-Cookie: evil=1", "/"},
		{"/path\nInjected-Header: 1", "/"},
		{"/path\x00nullbyte", "/"},
		{"javascript:alert(1)", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeRedirect(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeRedirect(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
