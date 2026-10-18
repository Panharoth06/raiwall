package bot

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/altcha-org/altcha-lib-go"
)

func TestPoWEngine_CreateAndSolve(t *testing.T) {
	engine := NewPoWEngine(PoWConfig{
		Secret:     "super-secret-hmac-key-test-123",
		Difficulty: 1000, // Small difficulty for fast test
		TTL:        2 * time.Minute,
	})

	challenge, err := engine.CreateChallenge()
	if err != nil {
		t.Fatalf("CreateChallenge() failed: %v", err)
	}

	if challenge.Algorithm != "SHA-256" {
		t.Errorf("Algorithm = %q, want SHA-256", challenge.Algorithm)
	}
	if challenge.Challenge == "" || challenge.Salt == "" || challenge.Signature == "" {
		t.Errorf("Challenge fields missing: %+v", challenge)
	}

	// Solve the challenge using altcha-lib-go solver
	solution, err := altcha.SolveChallenge(
		challenge.Challenge,
		challenge.Salt,
		altcha.SHA256,
		int(challenge.MaxNumber),
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("SolveChallenge() failed: %v", err)
	}

	payload := altcha.Payload{
		Algorithm: challenge.Algorithm,
		Challenge: challenge.Challenge,
		Number:    int64(solution.Number),
		Salt:      challenge.Salt,
		Signature: challenge.Signature,
	}

	// Verify valid solution
	valid, err := engine.VerifySolution(payload)
	if err != nil {
		t.Fatalf("VerifySolution() error: %v", err)
	}
	if !valid {
		t.Errorf("VerifySolution() returned false for valid solution")
	}

	// Test tampered number
	badPayload := payload
	badPayload.Number = badPayload.Number + 1
	validBad, err := engine.VerifySolution(badPayload)
	if validBad {
		t.Errorf("VerifySolution() returned true for tampered number")
	}

	// Test tampered signature
	badSigPayload := payload
	badSigPayload.Signature = "bad-sig-123"
	validBadSig, err := engine.VerifySolution(badSigPayload)
	if validBadSig {
		t.Errorf("VerifySolution() returned true for bad signature")
	}

	// Test replay prevention: submitting same valid solution a second time MUST FAIL
	validReplay, replayErr := engine.VerifySolution(payload)
	if validReplay || replayErr == nil {
		t.Fatalf("VerifySolution() accepted replayed solution: valid=%v, err=%v", validReplay, replayErr)
	}
	if !strings.Contains(replayErr.Error(), "replay detected") {
		t.Errorf("expected 'replay detected' in error, got: %v", replayErr)
	}

	// Test base64-encoded payload verification
	freshChallenge, err := engine.CreateChallenge()
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}
	freshSol, err := altcha.SolveChallenge(freshChallenge.Challenge, freshChallenge.Salt, altcha.SHA256, int(freshChallenge.MaxNumber), 0, nil)
	if err != nil {
		t.Fatalf("SolveChallenge failed: %v", err)
	}
	freshPayload := altcha.Payload{
		Algorithm: freshChallenge.Algorithm,
		Challenge: freshChallenge.Challenge,
		Number:    int64(freshSol.Number),
		Salt:      freshChallenge.Salt,
		Signature: freshChallenge.Signature,
	}
	b64Bytes, _ := json.Marshal(freshPayload)
	b64Str := base64.StdEncoding.EncodeToString(b64Bytes)

	validB64, err := engine.VerifySolution(b64Str)
	if err != nil || !validB64 {
		t.Fatalf("VerifySolution(base64) failed: valid=%v, err=%v", validB64, err)
	}
}

func TestPoWEngine_RenderChallengePage(t *testing.T) {
	engine := NewPoWEngine(PoWConfig{
		Secret:     "secret-key-pow-render",
		Difficulty: 5000,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected/resource", nil)

	err := engine.RenderChallengePage(rec, req, "/protected/resource")
	if err != nil {
		t.Fatalf("RenderChallengePage() failed: %v", err)
	}

	resp := rec.Result()
	if resp.StatusCode != HTTPStatusChallenge {
		t.Errorf("StatusCode = %d, want %d (HTTP 468)", resp.StatusCode, HTTPStatusChallenge)
	}

	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Protected by Raiwall Gateway Defense") {
		t.Errorf("Rendered HTML missing brand text")
	}
	if !strings.Contains(body, "window.crypto.subtle.digest") {
		t.Errorf("Rendered HTML missing WebCrypto solver")
	}
	if !strings.Contains(body, "/.raiwall/challenge/verify") {
		t.Errorf("Rendered HTML missing verification endpoint")
	}
}
