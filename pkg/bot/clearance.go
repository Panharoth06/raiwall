package bot

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ClearanceCookieName is the standard cookie name for clearance tokens.
const ClearanceCookieName = "rw_clearance"

// ChallengeVerifyPath is the internal endpoint handling PoW challenge submission.
const ChallengeVerifyPath = "/.raiwall/challenge/verify"

// DefaultClearanceTTL is the standard clearance duration (2 hours).
const DefaultClearanceTTL = 2 * time.Hour

// ClearanceConfig configures token generation and verification.
type ClearanceConfig struct {
	Secret string
	TTL    time.Duration
}

// ClearanceManager handles issuing and verifying tamper-proof HMAC clearance cookies.
type ClearanceManager struct {
	secret string
	ttl    time.Duration
	pow    *PoWEngine
}

// NewClearanceManager constructs an initialized ClearanceManager.
func NewClearanceManager(cfg ClearanceConfig, pow *PoWEngine) *ClearanceManager {
	secret := cfg.Secret
	if secret == "" {
		if pow != nil && pow.Secret() != "" {
			secret = pow.Secret()
		} else {
			b := make([]byte, 32)
			_, _ = rand.Read(b)
			secret = hex.EncodeToString(b)
		}
	}

	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultClearanceTTL
	}

	return &ClearanceManager{
		secret: secret,
		ttl:    ttl,
		pow:    pow,
	}
}

// GenerateToken creates a signed token bound to ClientIP + JA4 + Expiration.
func (cm *ClearanceManager) GenerateToken(clientIP net.IP, ja4 string, expires time.Time) string {
	expiresUnix := expires.Unix()
	ipStr := ""
	if clientIP != nil {
		ipStr = clientIP.String()
	}

	message := fmt.Sprintf("%s|%s|%d", ipStr, ja4, expiresUnix)
	mac := hmac.New(sha256.New, []byte(cm.secret))
	mac.Write([]byte(message))
	sigHex := hex.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%d.%s", expiresUnix, sigHex)
}

// ValidateToken verifies that a clearance token is syntactically valid, unexpired,
// and cryptographically matches the client IP and JA4 fingerprint.
func (cm *ClearanceManager) ValidateToken(token string, clientIP net.IP, ja4 string) bool {
	if token == "" {
		return false
	}

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}

	expiresUnix, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}

	// Expiration check
	if time.Now().Unix() > expiresUnix {
		return false
	}

	providedSig, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}

	ipStr := ""
	if clientIP != nil {
		ipStr = clientIP.String()
	}

	message := fmt.Sprintf("%s|%s|%d", ipStr, ja4, expiresUnix)
	mac := hmac.New(sha256.New, []byte(cm.secret))
	mac.Write([]byte(message))
	expectedSig := mac.Sum(nil)

	return hmac.Equal(expectedSig, providedSig)
}

// ValidateRequest checks if the incoming HTTP request has a valid rw_clearance cookie.
func (cm *ClearanceManager) ValidateRequest(r *http.Request, clientIP net.IP, ja4 string) bool {
	if r == nil {
		return false
	}

	cookie, err := r.Cookie(ClearanceCookieName)
	if err != nil || cookie == nil || cookie.Value == "" {
		return false
	}

	return cm.ValidateToken(cookie.Value, clientIP, ja4)
}

// IssueClearanceCookie attaches a new rw_clearance cookie to the response.
func (cm *ClearanceManager) IssueClearanceCookie(w http.ResponseWriter, r *http.Request, clientIP net.IP, ja4 string) string {
	expires := time.Now().Add(cm.ttl)
	token := cm.GenerateToken(clientIP, ja4, expires)

	isSecure := false
	if r != nil {
		if r.TLS != nil ||
			r.Header.Get("X-Forwarded-Proto") == "https" ||
			r.Header.Get("X-Forwarded-Ssl") == "on" {
			isSecure = true
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     ClearanceCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(cm.ttl.Seconds()),
		Expires:  expires,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})

	return token
}

type verifyRequestPayload struct {
	Payload  interface{} `json:"payload"`
	Redirect string      `json:"redirect"`
}

// HandleChallengeVerify processes PoW challenge submissions at /.raiwall/challenge/verify.
func (cm *ClearanceManager) HandleChallengeVerify(w http.ResponseWriter, r *http.Request, clientIP net.IP, ja4 string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if cm.pow == nil {
		http.Error(w, "PoW engine uninitialized", http.StatusInternalServerError)
		return
	}

	var rawPayload interface{}
	var redirectURL string

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err == nil {
			var reqData verifyRequestPayload
			if jsonErr := json.Unmarshal(bodyBytes, &reqData); jsonErr == nil {
				rawPayload = reqData.Payload
				redirectURL = reqData.Redirect
			}
		}
	} else {
		// Form-encoded submission
		_ = r.ParseForm()
		rawPayload = r.FormValue("payload")
		if rawPayload == "" {
			rawPayload = r.FormValue("altcha")
		}
		redirectURL = r.FormValue("redirect")
	}

	// Validate solution against PoW engine
	valid, err := cm.pow.VerifySolution(rawPayload)
	if err != nil || !valid {
		if strings.Contains(r.Header.Get("Accept"), "application/json") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "invalid challenge solution",
			})
			return
		}
		http.Error(w, "Invalid challenge verification", http.StatusBadRequest)
		return
	}

	// Challenge solved: issue clearance cookie
	cm.IssueClearanceCookie(w, r, clientIP, ja4)

	// Sanitize redirect target URL (prevent open redirect attacks and CRLF injection)
	redirectURL = sanitizeRedirect(redirectURL)

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"redirect": redirectURL,
		})
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// sanitizeRedirect ensures the redirect target is a safe relative URL.
// It guards against open redirects, protocol-relative URLs (//evil.com), backslashes, CRLF injection, and control characters.
func sanitizeRedirect(target string) string {
	target = strings.TrimSpace(target)
	if target == "" || !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") || strings.HasPrefix(target, "/\\") {
		return "/"
	}

	// Reject CRLF and control characters to prevent response splitting
	for i := 0; i < len(target); i++ {
		if target[i] < 32 || target[i] == 127 {
			return "/"
		}
	}

	u, err := url.Parse(target)
	if err != nil || u.Host != "" || u.Scheme != "" || strings.HasPrefix(u.Path, "//") {
		return "/"
	}

	return target
}
