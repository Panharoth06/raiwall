package bot

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/altcha-org/altcha-lib-go"
)

// DefaultPoWDifficulty is the standard number of iterations for the WebCrypto PoW solver (~100-300ms on modern client).
const DefaultPoWDifficulty int64 = 50000

// DefaultPoWTTL is the expiration lifespan of an issued challenge.
const DefaultPoWTTL = 5 * time.Minute

// PoWConfig configures the proof-of-work challenge engine.
type PoWConfig struct {
	Secret     string
	Difficulty int64
	TTL        time.Duration
}

// PoWEngine manages generation, rendering, and verification of stateless Altcha PoW challenges.
type PoWEngine struct {
	secret     string
	difficulty int64
	ttl        time.Duration
	tmpl       *template.Template

	mu            sync.Mutex
	redeemedSalts map[string]time.Time
}

// NewPoWEngine constructs an initialized PoWEngine.
func NewPoWEngine(cfg PoWConfig) *PoWEngine {
	secret := cfg.Secret
	if secret == "" {
		// Generate 32-byte cryptographically secure random secret
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		secret = hex.EncodeToString(b)
	}

	difficulty := cfg.Difficulty
	if difficulty <= 0 {
		difficulty = DefaultPoWDifficulty
	}

	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultPoWTTL
	}

	tmpl := template.Must(template.New("challenge").Parse(challengeHTMLTemplate))

	return &PoWEngine{
		secret:        secret,
		difficulty:    difficulty,
		ttl:           ttl,
		tmpl:          tmpl,
		redeemedSalts: make(map[string]time.Time),
	}
}

// Secret returns the active HMAC key.
func (p *PoWEngine) Secret() string {
	return p.secret
}

// Difficulty returns the configured max number.
func (p *PoWEngine) Difficulty() int64 {
	return p.difficulty
}

// CreateChallenge generates a stateless Altcha proof-of-work challenge signed with the engine secret.
func (p *PoWEngine) CreateChallenge() (altcha.Challenge, error) {
	expiresAt := time.Now().Add(p.ttl)
	opts := altcha.ChallengeOptions{
		Algorithm:  altcha.SHA256,
		MaxNumber:  p.difficulty,
		SaltLength: 12,
		HMACKey:    p.secret,
		Expires:    &expiresAt,
	}

	ch, err := altcha.CreateChallenge(opts)
	if err != nil {
		return altcha.Challenge{}, fmt.Errorf("create altcha challenge: %w", err)
	}
	return ch, nil
}

// VerifySolution validates an Altcha solution payload against the engine secret.
// It enforces replay prevention by ensuring that the challenge salt cannot be redeemed more than once.
func (p *PoWEngine) VerifySolution(payload interface{}) (bool, error) {
	if payload == nil {
		return false, fmt.Errorf("payload is nil")
	}

	var salt string
	switch v := payload.(type) {
	case altcha.Payload:
		salt = v.Salt
	case *altcha.Payload:
		if v != nil {
			salt = v.Salt
		}
	case string:
		var pl altcha.Payload
		if err := json.Unmarshal([]byte(v), &pl); err == nil && pl.Challenge != "" {
			payload = pl
			salt = pl.Salt
		} else if b64, b64Err := base64.StdEncoding.DecodeString(v); b64Err == nil {
			if err := json.Unmarshal(b64, &pl); err == nil && pl.Challenge != "" {
				payload = pl
				salt = pl.Salt
			}
		}
	case map[string]interface{}:
		if s, ok := v["salt"].(string); ok {
			salt = s
		}
		b, err := json.Marshal(v)
		if err == nil {
			var pl altcha.Payload
			if err := json.Unmarshal(b, &pl); err == nil && pl.Challenge != "" {
				payload = pl
				if salt == "" {
					salt = pl.Salt
				}
			}
		}
	}

	// 1. Replay prevention check
	now := time.Now()
	if salt != "" {
		p.mu.Lock()
		if exp, exists := p.redeemedSalts[salt]; exists && now.Before(exp) {
			p.mu.Unlock()
			return false, fmt.Errorf("challenge replay detected: salt %q has already been redeemed", salt)
		}
		p.mu.Unlock()
	}

	// 2. Cryptographic verification
	valid, err := altcha.VerifySolution(payload, p.secret, true)
	if err != nil {
		return false, fmt.Errorf("verify altcha solution: %w", err)
	}

	// 3. Record redeemed salt
	if valid && salt != "" {
		p.mu.Lock()
		p.redeemedSalts[salt] = now.Add(p.ttl)
		if len(p.redeemedSalts) > 1000 {
			for s, exp := range p.redeemedSalts {
				if now.After(exp) {
					delete(p.redeemedSalts, s)
				}
			}
		}
		p.mu.Unlock()
	}

	return valid, nil
}

// RenderChallengePage renders and writes the complete self-contained HTTP 468 challenge response.
func (p *PoWEngine) RenderChallengePage(w http.ResponseWriter, r *http.Request, returnURL string) error {
	ch, err := p.CreateChallenge()
	if err != nil {
		return err
	}

	chJSON, err := json.Marshal(ch)
	if err != nil {
		return fmt.Errorf("marshal challenge: %w", err)
	}

	if returnURL == "" && r != nil {
		returnURL = r.URL.RequestURI()
	}
	if returnURL == "" {
		returnURL = "/"
	}

	data := struct {
		ChallengeJSON template.JS
		RedirectURL   string
	}{
		ChallengeJSON: template.JS(string(chJSON)),
		RedirectURL:   returnURL,
	}

	buf := new(bytes.Buffer)
	if err := p.tmpl.Execute(buf, data); err != nil {
		return fmt.Errorf("render challenge template: %w", err)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(HTTPStatusChallenge)

	_, err = w.Write(buf.Bytes())
	return err
}
