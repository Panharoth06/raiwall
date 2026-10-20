package bot

import (
	"net"
	"net/http"

	"github.com/altcha-org/altcha-lib-go"
)

// BotDefensePort defines the driving port for bot defense, classification, and mitigation.
type BotDefensePort interface {
	Classify(req *http.Request, ip net.IP, ja4 string) *BotVerdict
	CreateChallenge() (altcha.Challenge, error)
	ValidateClearance(token string, ip net.IP, ja4 string) bool
}

// ClearancePort defines the driven/driving port for clearance token generation and verification.
type ClearancePort interface {
	GenerateToken(ip net.IP, ja4 string) string
	ValidateToken(token string, ip net.IP, ja4 string) bool
}
