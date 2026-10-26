package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// SiteDTO represents application domain configuration.
type SiteDTO struct {
	ID                  string                   `json:"id"`
	Name                string                   `json:"name"`
	Description         string                   `json:"description,omitempty"`
	Hostnames           []string                 `json:"hostnames"`
	Mode                string                   `json:"mode"`
	Ports               []control.ListeningPort  `json:"ports"`
	SSLMode             string                   `json:"ssl_mode"`
	CertificateID       string                   `json:"certificate_id,omitempty"`
	RoutingType         string                   `json:"routing_type"`
	DocumentRoot        string                   `json:"document_root,omitempty"`
	RedirectURL         string                   `json:"redirect_url,omitempty"`
	RedirectStatus      int                      `json:"redirect_status,omitempty"`
	LoadBalancing       string                   `json:"load_balancing"`
	Upstreams           []control.UpstreamTarget `json:"upstreams"`
	ForwardingRules     []control.ForwardingRule `json:"forwarding_rules,omitempty"`
	ProxySettings       *control.ProxySettings   `json:"proxy_settings,omitempty"`
	BlockStatusCode     int                      `json:"block_status_code"`
	BlockResponseBody   string                   `json:"block_response_body"`
	OfflineStatusCode   int                      `json:"offline_status_code"`
	OfflineResponseBody string                   `json:"offline_response_body"`
	CustomHeaders       map[string]string        `json:"custom_headers"`
	AuthEnabled         bool                     `json:"auth_enabled,omitempty"`
	AuthBypassPaths     []string                 `json:"auth_bypass_paths,omitempty"`
	CreatedAt           time.Time                `json:"created_at"`
	UpdatedAt           time.Time                `json:"updated_at"`
}

// siteDTOFromRecord decodes a persisted application row into its API shape.
func siteDTOFromRecord(app control.SiteApp) SiteDTO {
	var hostnames []string
	_ = json.Unmarshal([]byte(app.Hostnames), &hostnames)
	var upstreams []control.UpstreamTarget
	_ = json.Unmarshal([]byte(app.Upstreams), &upstreams)
	var headers map[string]string
	_ = json.Unmarshal([]byte(app.CustomHeaders), &headers)
	var proxySettings *control.ProxySettings
	if raw := strings.TrimSpace(app.ProxySettings); raw != "" && raw != "null" {
		var ps control.ProxySettings
		if err := json.Unmarshal([]byte(raw), &ps); err == nil {
			proxySettings = &ps
		}
	}
	var ports []control.ListeningPort
	if app.Ports != "" {
		_ = json.Unmarshal([]byte(app.Ports), &ports)
	}

	dto := SiteDTO{
		ID:                  app.ID,
		Name:                app.Name,
		Description:         app.Description,
		Hostnames:           hostnames,
		Mode:                app.Mode,
		Ports:               ports,
		SSLMode:             app.SSLMode,
		CertificateID:       app.CertificateID,
		RoutingType:         app.RoutingType,
		DocumentRoot:        app.DocumentRoot,
		RedirectURL:         app.RedirectURL,
		RedirectStatus:      int(app.RedirectStatus),
		LoadBalancing:       app.LoadBalancing,
		Upstreams:           upstreams,
		ProxySettings:       proxySettings,
		BlockStatusCode:     int(app.BlockStatusCode),
		BlockResponseBody:   app.BlockResponseBody,
		OfflineStatusCode:   int(app.OfflineStatusCode),
		OfflineResponseBody: app.OfflineResponseBody,
		CustomHeaders:       headers,
		AuthEnabled:         app.AuthEnabled == 1,
		AuthBypassPaths:     parseBypassPaths(app.AuthBypassPaths),
		CreatedAt:           app.CreatedAt,
		UpdatedAt:           app.UpdatedAt,
	}
	if dto.Ports == nil {
		dto.Ports = []control.ListeningPort{{Port: 80, Scheme: "http"}}
	}
	if dto.SSLMode == "" {
		dto.SSLMode = control.SSLModeNone
	}
	if dto.RoutingType == "" {
		dto.RoutingType = control.RoutingProxy
	}
	if dto.LoadBalancing == "" {
		dto.LoadBalancing = control.LoadBalanceRoundRobin
	}
	if dto.RedirectStatus == 0 {
		dto.RedirectStatus = 302
	}
	return dto
}

// siteRecordFromDTO normalizes and validates an application request payload.
func (s *Server) siteRecordFromDTO(ctx context.Context, req SiteDTO, id string, now time.Time) (control.SiteApp, error) {
	hostnames := make([]string, 0, len(req.Hostnames))
	for _, host := range req.Hostnames {
		clean := strings.TrimSpace(host)
		if clean != "" {
			hostnames = append(hostnames, clean)
		}
	}
	if len(hostnames) == 0 {
		return control.SiteApp{}, fmt.Errorf("at least one hostname is required")
	}

	routing, err := control.NormalizeRoutingType(req.RoutingType)
	if err != nil {
		return control.SiteApp{}, err
	}
	sslMode, err := control.NormalizeSSLMode(req.SSLMode)
	if err != nil {
		return control.SiteApp{}, err
	}
	balancing, err := control.NormalizeLoadBalancing(req.LoadBalancing)
	if err != nil {
		return control.SiteApp{}, err
	}
	ports, err := control.NormalizePorts(req.Ports)
	if err != nil {
		return control.SiteApp{}, err
	}
	if control.HasHTTPSPort(ports) && sslMode == control.SSLModeNone {
		return control.SiteApp{}, fmt.Errorf("an https listening port requires ssl_mode 'auto' or 'manual'")
	}

	if routing == control.RoutingProxy {
		for idx, up := range req.Upstreams {
			if strings.TrimSpace(up.Dial) == "" {
				return control.SiteApp{}, fmt.Errorf("upstream %d requires a dial address (host:port or unix:/path)", idx)
			}
			if !isValidUpstreamDial(up.Dial) {
				return control.SiteApp{}, fmt.Errorf("upstream %d has an invalid dial address %q (expected host:port or unix:/path)", idx, up.Dial)
			}
			if up.Weight < 0 {
				return control.SiteApp{}, fmt.Errorf("upstream %d weight must be non-negative", idx)
			}
		}
	}

	redirectStatus := req.RedirectStatus
	if redirectStatus == 0 {
		redirectStatus = 302
	}
	switch routing {
	case control.RoutingStatic:
		if strings.TrimSpace(req.DocumentRoot) == "" {
			return control.SiteApp{}, fmt.Errorf("static routing requires a document root")
		}
		if !filepath.IsAbs(req.DocumentRoot) {
			return control.SiteApp{}, fmt.Errorf("document root must be an absolute path")
		}
	case control.RoutingRedirect:
		if !control.IsValidRedirectTarget(req.RedirectURL) {
			return control.SiteApp{}, fmt.Errorf("redirect routing requires an absolute http(s) URL or a site-relative path")
		}
		if !control.IsValidRedirectStatus(redirectStatus) {
			return control.SiteApp{}, fmt.Errorf("unsupported redirect status %d", redirectStatus)
		}
	}

	if sslMode == control.SSLModeManual {
		if strings.TrimSpace(req.CertificateID) == "" {
			return control.SiteApp{}, fmt.Errorf("ssl_mode 'manual' requires a certificate_id")
		}
		if err := s.validateCertificateCoverage(ctx, req.CertificateID, hostnames); err != nil {
			return control.SiteApp{}, err
		}
	}

	mode := req.Mode
	if mode == "" {
		mode = string(control.ModeDefense)
	}
	if !control.RunMode(mode).IsValid() {
		return control.SiteApp{}, fmt.Errorf("invalid run mode %q", mode)
	}

	blockCode := req.BlockStatusCode
	if blockCode == 0 {
		blockCode = 403
	}
	offlineCode := req.OfflineStatusCode
	if offlineCode == 0 {
		offlineCode = 503
	}

	hostnamesJSON, _ := json.Marshal(hostnames)
	upstreamsJSON, _ := json.Marshal(req.Upstreams)
	headersJSON, _ := json.Marshal(req.CustomHeaders)
	proxySettingsJSON := ""
	if req.ProxySettings != nil {
		raw, _ := json.Marshal(req.ProxySettings)
		proxySettingsJSON = string(raw)
	}
	bypassPathsJSON := marshalBypassPaths(req.AuthBypassPaths)
	portsJSON, _ := json.Marshal(ports)

	return control.SiteApp{
		ID:                  id,
		Name:                req.Name,
		Hostnames:           string(hostnamesJSON),
		Mode:                mode,
		Upstreams:           string(upstreamsJSON),
		BlockStatusCode:     int64(blockCode),
		BlockResponseBody:   req.BlockResponseBody,
		OfflineStatusCode:   int64(offlineCode),
		OfflineResponseBody: req.OfflineResponseBody,
		CustomHeaders:       string(headersJSON),
		ProxySettings:       proxySettingsJSON,
		AuthEnabled:         boolToInt64(req.AuthEnabled),
		AuthBypassPaths:     string(bypassPathsJSON),
		Description:         strings.TrimSpace(req.Description),
		Ports:               string(portsJSON),
		SSLMode:             sslMode,
		CertificateID:       req.CertificateID,
		RoutingType:         routing,
		DocumentRoot:        strings.TrimSpace(req.DocumentRoot),
		RedirectURL:         strings.TrimSpace(req.RedirectURL),
		RedirectStatus:      int64(redirectStatus),
		LoadBalancing:       balancing,
		CreatedAt:           now,
		UpdatedAt:           now,
	}, nil
}

// validateCertificateCoverage ensures a manually selected certificate covers
// every hostname of the application.
func (s *Server) validateCertificateCoverage(ctx context.Context, certID string, hostnames []string) error {
	record, err := s.store.GetCertificate(ctx, certID)
	if err != nil {
		return fmt.Errorf("certificate %q not found", certID)
	}
	leaf, err := control.ParseLeafCertificate(record.CertPEM)
	if err != nil {
		return fmt.Errorf("certificate %q has no usable public certificate", certID)
	}
	for _, host := range hostnames {
		clean := strings.ToLower(strings.TrimSpace(host))
		if clean == "*" || strings.HasPrefix(clean, "*.") {
			continue
		}
		if !control.CertificateCoversDomain(leaf, clean) {
			return fmt.Errorf("certificate %q does not cover hostname %q", record.Name, host)
		}
	}
	return nil
}

// isValidUpstreamDial accepts host:port pairs and unix domain sockets.
func isValidUpstreamDial(addr string) bool {
	clean := strings.TrimSpace(addr)
	if strings.HasPrefix(clean, "unix:") {
		return len(clean) > len("unix:")
	}
	host, port, err := net.SplitHostPort(clean)
	if err != nil {
		return false
	}
	if port == "" {
		return false
	}
	if _, err := strconv.Atoi(port); err != nil {
		return false
	}
	return host != ""
}
