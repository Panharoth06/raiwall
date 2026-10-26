package control

import (
	"fmt"
	"net/url"
	"strings"
)

// ListeningPort is the declarative port metadata exposed for a protected site.
// The data plane itself binds the shared gateway listeners; ports are used for
// validation, HTTP→HTTPS upgrades, and operator-facing reporting.
type ListeningPort struct {
	Port   int    `json:"port"`
	Scheme string `json:"scheme"`
}

// TLS mode for a protected application.
const (
	SSLModeNone   = "none"
	SSLModeAuto   = "auto"
	SSLModeManual = "manual"
)

// Routing strategies for a protected application.
const (
	RoutingProxy    = "proxy"
	RoutingStatic   = "static"
	RoutingRedirect = "redirect"
)

// Upstream load-balancing policies.
const (
	LoadBalanceRoundRobin    = "round_robin"
	LoadBalanceLeastConn     = "least_conn"
	LoadBalanceIPHash        = "ip_hash"
	LoadBalancePrimaryBackup = "primary_backup"
)

// Certificate sources.
const (
	CertSourceUpload     = "upload"
	CertSourceSelfSigned = "self_signed"
	CertSourceACME       = "acme"
)

// NormalizeSSLMode validates and normalizes a TLS mode, defaulting to "none".
func NormalizeSSLMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", SSLModeNone:
		return SSLModeNone, nil
	case SSLModeAuto:
		return SSLModeAuto, nil
	case SSLModeManual:
		return SSLModeManual, nil
	default:
		return "", fmt.Errorf("invalid ssl_mode %q (expected none, auto, or manual)", mode)
	}
}

// NormalizeRoutingType validates and normalizes an application routing strategy.
func NormalizeRoutingType(routing string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(routing)) {
	case "", RoutingProxy:
		return RoutingProxy, nil
	case RoutingStatic:
		return RoutingStatic, nil
	case RoutingRedirect:
		return RoutingRedirect, nil
	default:
		return "", fmt.Errorf("invalid routing_type %q (expected proxy, static, or redirect)", routing)
	}
}

// NormalizeLoadBalancing validates and normalizes an upstream balancing policy.
func NormalizeLoadBalancing(policy string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "", LoadBalanceRoundRobin:
		return LoadBalanceRoundRobin, nil
	case LoadBalanceLeastConn:
		return LoadBalanceLeastConn, nil
	case LoadBalanceIPHash:
		return LoadBalanceIPHash, nil
	case LoadBalancePrimaryBackup:
		return LoadBalancePrimaryBackup, nil
	default:
		return "", fmt.Errorf("invalid load_balancing %q (expected round_robin, least_conn, ip_hash, or primary_backup)", policy)
	}
}

// NormalizePorts validates declared listening ports.
func NormalizePorts(ports []ListeningPort) ([]ListeningPort, error) {
	if len(ports) == 0 {
		return []ListeningPort{{Port: 80, Scheme: "http"}}, nil
	}
	seen := make(map[int]struct{}, len(ports))
	out := make([]ListeningPort, 0, len(ports))
	for _, p := range ports {
		if p.Port < 1 || p.Port > 65535 {
			return nil, fmt.Errorf("invalid port %d (must be 1-65535)", p.Port)
		}
		scheme := strings.ToLower(strings.TrimSpace(p.Scheme))
		if scheme == "" {
			scheme = "http"
		}
		if scheme != "http" && scheme != "https" {
			return nil, fmt.Errorf("invalid port scheme %q (expected http or https)", p.Scheme)
		}
		if _, dup := seen[p.Port]; dup {
			return nil, fmt.Errorf("duplicate port %d", p.Port)
		}
		seen[p.Port] = struct{}{}
		out = append(out, ListeningPort{Port: p.Port, Scheme: scheme})
	}
	return out, nil
}

// HasHTTPSPort reports whether the application declares any HTTPS port.
func HasHTTPSPort(ports []ListeningPort) bool {
	for _, p := range ports {
		if p.Scheme == "https" {
			return true
		}
	}
	return false
}

// IsValidRedirectTarget accepts absolute http(s) URLs and site-relative paths.
func IsValidRedirectTarget(target string) bool {
	clean := strings.TrimSpace(target)
	if clean == "" {
		return false
	}
	if strings.HasPrefix(clean, "/") && !strings.HasPrefix(clean, "//") {
		return true
	}
	u, err := url.Parse(clean)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// IsValidRedirectStatus restricts redirects to permanent or temporary codes.
func IsValidRedirectStatus(status int) bool {
	return status == 301 || status == 302 || status == 307 || status == 308
}
