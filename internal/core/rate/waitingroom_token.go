package rate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// GenerateAdmissionToken signs an admission token bound to IP and JA4.
func (wm *WaitingRoomManager) GenerateAdmissionToken(ip net.IP, ja4 string, ttl time.Duration) string {
	if ttl == 0 {
		ttl = wm.admissionTokenTTL
	}
	ipStr := ""
	if ip != nil {
		ipStr = ip.String()
	}

	expiresAt := time.Now().Add(ttl).Unix()
	payload := fmt.Sprintf("%d:%s:%s", expiresAt, ipStr, ja4)

	mac := hmac.New(sha256.New, wm.secret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s:%s", payload, sig)
}

// ValidateAdmissionToken verifies that token is authentic, unexpired, and bound to IP + JA4.
func (wm *WaitingRoomManager) ValidateAdmissionToken(token string, ip net.IP, ja4 string) bool {
	parts := strings.Split(token, ":")
	if len(parts) != 4 {
		return false
	}

	expiresAtUnix, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}

	if time.Now().Unix() > expiresAtUnix {
		return false // Expired
	}

	tokenIP := parts[1]
	tokenJA4 := parts[2]
	providedSig := parts[3]

	ipStr := ""
	if ip != nil {
		ipStr = ip.String()
	}

	// Verify IP binding if token was bound to an IP
	if tokenIP != "" && ipStr != "" && tokenIP != ipStr {
		return false
	}
	// Verify JA4 binding if token was bound to JA4
	if tokenJA4 != "" && ja4 != "" && tokenJA4 != ja4 {
		return false
	}

	payload := fmt.Sprintf("%d:%s:%s", expiresAtUnix, tokenIP, tokenJA4)
	mac := hmac.New(sha256.New, wm.secret)
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(providedSig), []byte(expectedSig))
}

// IsAdmitted checks if incoming request carries a valid admission token.
func (wm *WaitingRoomManager) IsAdmitted(r *http.Request, ip net.IP, ja4 string) bool {
	if r == nil {
		return false
	}

	// 1. Check header
	if token := r.Header.Get("X-Raiwall-Admission-Token"); token != "" {
		if wm.ValidateAdmissionToken(token, ip, ja4) {
			return true
		}
	}

	// 2. Check clearance cookie
	if cookie, err := r.Cookie(WaitingRoomClearanceCookie); err == nil && cookie.Value != "" {
		if wm.ValidateAdmissionToken(cookie.Value, ip, ja4) {
			return true
		}
	}

	return false
}
