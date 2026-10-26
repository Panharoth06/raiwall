package declarative

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/config"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
)

// syncApplications materializes protected applications and their forwarding
// rules. Certificates must already be synced so manual references resolve.
func (s *syncer) syncApplications(apps []config.Application) error {
	existing, err := s.store.ListApps(s.ctx)
	if err != nil {
		return err
	}
	byID := make(map[string]control.SiteApp, len(existing))
	hostOwner := make(map[string]control.SiteApp, len(existing))
	ids := make([]string, 0, len(existing))
	for _, app := range existing {
		byID[app.ID] = app
		ids = append(ids, app.ID)
		for _, host := range decodeStrings(app.Hostnames) {
			hostOwner[strings.ToLower(strings.TrimSpace(host))] = app
		}
	}

	certs, err := s.store.ListCertificates(s.ctx)
	if err != nil {
		return err
	}
	certIDs := make(map[string]string, len(certs))
	for _, cert := range certs {
		certIDs[cert.Name] = cert.ID
	}

	declared := make(map[string]struct{}, len(apps))
	for _, app := range apps {
		id := namedID(KindApplication, app.Name)
		declared[id] = struct{}{}

		prev, exists := byID[id]
		if !exists {
			if owner, conflict := conflictingHost(app.Hostnames, hostOwner, id); conflict {
				if err := s.conflict("application hostname "+owner, app.Name); err != nil {
					return err
				}
				continue
			}
		}
		if exists && !s.canWrite(true) {
			continue
		}

		rec, err := buildApplication(app, id, prev, certIDs)
		if err != nil {
			if ferr := s.handle("application", app.Name, err); ferr != nil {
				return ferr
			}
			continue
		}

		if exists {
			if !sameApplication(prev, rec) {
				if err := s.store.UpdateApp(s.ctx, rec); err != nil {
					if ferr := s.handle("application", app.Name, err); ferr != nil {
						return ferr
					}
					continue
				}
				s.result.Updated++
			}
		} else {
			if err := s.store.CreateApp(s.ctx, rec); err != nil {
				if ferr := s.handle("application", app.Name, err); ferr != nil {
					return ferr
				}
				continue
			}
			s.result.Created++
		}

		if err := s.syncForwarding(id, app.Forwarding); err != nil {
			if ferr := s.handle("forwarding", app.Name, err); ferr != nil {
				return ferr
			}
		}
		if err := s.syncAppSemantic(id, app.Semantic); err != nil {
			if ferr := s.handle("semantic policy", app.Name, err); ferr != nil {
				return ferr
			}
		}
	}

	return s.pruneIDs(KindApplication, declared, ids, func(id string) error {
		_ = s.store.DeleteForwardingRulesByApp(s.ctx, id)
		_ = s.store.DeleteAppSemanticPolicy(s.ctx, id)
		return s.store.DeleteApp(s.ctx, id)
	})
}

func buildApplication(app config.Application, id string, prev control.SiteApp, certIDs map[string]string) (control.SiteApp, error) {
	hostnames := normalizeStrings(app.Hostnames)
	if len(hostnames) == 0 {
		return control.SiteApp{}, fmt.Errorf("at least one hostname is required")
	}
	mode, err := control.ParseRunMode(app.Mode)
	if err != nil {
		return control.SiteApp{}, err
	}
	routing, err := control.NormalizeRoutingType(app.RoutingType)
	if err != nil {
		return control.SiteApp{}, err
	}
	sslMode, err := control.NormalizeSSLMode(app.SSLMode)
	if err != nil {
		return control.SiteApp{}, err
	}
	balancing, err := control.NormalizeLoadBalancing(app.LoadBalancing)
	if err != nil {
		return control.SiteApp{}, err
	}

	ports := make([]control.ListeningPort, 0, len(app.Ports))
	for _, port := range app.Ports {
		ports = append(ports, control.ListeningPort{Port: port.Port, Scheme: port.Scheme})
	}
	normalizedPorts, err := control.NormalizePorts(ports)
	if err != nil {
		return control.SiteApp{}, err
	}

	certID := ""
	if sslMode == control.SSLModeManual {
		certID = certIDs[app.Certificate]
		if certID == "" {
			return control.SiteApp{}, fmt.Errorf("certificate %q is not declared or stored", app.Certificate)
		}
	}

	upstreams := make([]control.UpstreamTarget, 0, len(app.Upstreams))
	for _, up := range app.Upstreams {
		upstreams = append(upstreams, control.UpstreamTarget{
			Dial:                strings.TrimSpace(up.Dial),
			Weight:              up.Weight,
			MaxFails:            up.MaxFails,
			FailTimeout:         up.FailTimeout.Std(),
			HealthCheckPath:     up.HealthCheckPath,
			HealthCheckInterval: up.HealthCheckInterval.Std(),
		})
	}

	hostnamesJSON, _ := json.Marshal(hostnames)
	upstreamsJSON, _ := json.Marshal(upstreams)
	headersJSON, _ := json.Marshal(app.CustomHeaders)
	portsJSON, _ := json.Marshal(normalizedPorts)
	proxyJSON := ""
	if app.Proxy != nil {
		raw, _ := json.Marshal(control.ProxySettings{
			ClientIPSource:    app.Proxy.ClientIPSource,
			RewriteXFF:        app.Proxy.RewriteXFF,
			HSTS:              app.Proxy.HSTS,
			EnableSSE:         app.Proxy.EnableSSE,
			EnableCompression: app.Proxy.EnableCompression,
			EnableIPv6:        app.Proxy.EnableIPv6,
			RedirectHTTP:      app.Proxy.RedirectHTTP,
		})
		proxyJSON = string(raw)
	}
	bypassJSON := "[]"
	authEnabled := int64(0)
	if app.Auth != nil {
		bypass, _ := json.Marshal(app.Auth.BypassPaths)
		bypassJSON = string(bypass)
		authEnabled = boolToInt(app.Auth.Enabled)
	}

	now := time.Now().UTC()
	rec := control.SiteApp{
		ID:                  id,
		Name:                app.Name,
		Hostnames:           string(hostnamesJSON),
		Mode:                string(mode),
		Upstreams:           string(upstreamsJSON),
		BlockStatusCode:     statusOrDefault(app.BlockStatusCode, 403),
		BlockResponseBody:   app.BlockResponseBody,
		OfflineStatusCode:   statusOrDefault(app.OfflineStatusCode, 503),
		OfflineResponseBody: app.OfflineResponseBody,
		CustomHeaders:       string(headersJSON),
		ProxySettings:       proxyJSON,
		AuthEnabled:         authEnabled,
		AuthBypassPaths:     bypassJSON,
		Description:         strings.TrimSpace(app.Description),
		Ports:               string(portsJSON),
		SSLMode:             sslMode,
		CertificateID:       certID,
		RoutingType:         routing,
		DocumentRoot:        strings.TrimSpace(app.DocumentRoot),
		RedirectURL:         strings.TrimSpace(app.RedirectURL),
		RedirectStatus:      int64(redirectStatus(app.RedirectStatus)),
		LoadBalancing:       balancing,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if !prev.CreatedAt.IsZero() {
		rec.CreatedAt = prev.CreatedAt
	}
	return rec, nil
}

func (s *syncer) syncForwarding(appID string, rules []config.ForwardingRule) error {
	existing, err := s.store.ListForwardingRulesByApp(s.ctx, appID)
	if err != nil {
		return err
	}
	byID := make(map[string]control.ForwardingRuleRecord, len(existing))
	ids := make([]string, 0, len(existing))
	for _, rule := range existing {
		byID[rule.ID] = rule
		ids = append(ids, rule.ID)
	}

	declared := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		prefix := strings.TrimSpace(rule.Prefix)
		if prefix == "" {
			return fmt.Errorf("forwarding rule requires a prefix")
		}
		id := hashedID(KindForwarding, appID, prefix)
		declared[id] = struct{}{}

		upstreams := make([]control.UpstreamTarget, 0, len(rule.Upstreams))
		for _, up := range rule.Upstreams {
			upstreams = append(upstreams, control.UpstreamTarget{
				Dial:                strings.TrimSpace(up.Dial),
				Weight:              up.Weight,
				MaxFails:            up.MaxFails,
				FailTimeout:         up.FailTimeout.Std(),
				HealthCheckPath:     up.HealthCheckPath,
				HealthCheckInterval: up.HealthCheckInterval.Std(),
			})
		}
		upstreamJSON, _ := json.Marshal(upstreams)
		now := time.Now().UTC()
		prev, exists := byID[id]
		rec := control.ForwardingRuleRecord{
			ID:                 id,
			AppID:              appID,
			Prefix:             prefix,
			Upstreams:          string(upstreamJSON),
			StripPrefix:        boolToInt(rule.StripPrefix),
			HostHeaderOverride: rule.HostHeaderOverride,
			Comment:            rule.Comment,
			IsActive:           1,
			CreatedAt:          now,
			UpdatedAt:          now,
		}
		if exists && !s.canWrite(true) {
			continue
		}
		if !prev.CreatedAt.IsZero() {
			rec.CreatedAt = prev.CreatedAt
		}
		if exists {
			if sameForwarding(prev, rec) {
				continue
			}
			if err := s.store.UpdateForwardingRule(s.ctx, rec); err != nil {
				return err
			}
			s.result.Updated++
			continue
		}
		if err := s.store.CreateForwardingRule(s.ctx, rec); err != nil {
			return err
		}
		s.result.Created++
	}

	return s.pruneIDs(KindForwarding, declared, ids, func(id string) error {
		return s.store.DeleteForwardingRule(s.ctx, id)
	})
}

func (s *syncer) syncAppSemantic(appID string, policy map[string]string) error {
	if len(policy) == 0 {
		if s.prune {
			return s.store.DeleteAppSemanticPolicy(s.ctx, appID)
		}
		return nil
	}
	overrides := make(map[waf.Module]waf.ModuleMode, len(policy))
	for name, mode := range policy {
		module := waf.Module(name)
		if !waf.IsValidModule(module) {
			return fmt.Errorf("unknown semantic module %q", name)
		}
		parsed, err := waf.ParseModuleModeString(mode)
		if err != nil {
			return err
		}
		overrides[module] = parsed
	}
	encoded, _ := json.Marshal(overrides)
	return s.store.UpsertAppSemanticPolicy(s.ctx, control.AppSemanticPolicyRecord{
		AppID:     appID,
		Policy:    string(encoded),
		UpdatedAt: time.Now().UTC(),
	})
}

func conflictingHost(hostnames []string, owners map[string]control.SiteApp, selfID string) (string, bool) {
	for _, host := range normalizeStrings(hostnames) {
		owner, ok := owners[host]
		if !ok || owner.ID == selfID || IsManaged(owner.ID) {
			continue
		}
		return host, true
	}
	return "", false
}

func sameApplication(a, b control.SiteApp) bool {
	return a.Name == b.Name && a.Hostnames == b.Hostnames && a.Mode == b.Mode &&
		a.Upstreams == b.Upstreams && a.BlockStatusCode == b.BlockStatusCode &&
		a.BlockResponseBody == b.BlockResponseBody && a.OfflineStatusCode == b.OfflineStatusCode &&
		a.OfflineResponseBody == b.OfflineResponseBody && a.CustomHeaders == b.CustomHeaders &&
		a.ProxySettings == b.ProxySettings && a.AuthEnabled == b.AuthEnabled &&
		a.AuthBypassPaths == b.AuthBypassPaths && a.Description == b.Description &&
		a.Ports == b.Ports && a.SSLMode == b.SSLMode && a.CertificateID == b.CertificateID &&
		a.RoutingType == b.RoutingType && a.DocumentRoot == b.DocumentRoot &&
		a.RedirectURL == b.RedirectURL && a.RedirectStatus == b.RedirectStatus &&
		a.LoadBalancing == b.LoadBalancing
}

func sameForwarding(a, b control.ForwardingRuleRecord) bool {
	return a.Prefix == b.Prefix && a.Upstreams == b.Upstreams && a.StripPrefix == b.StripPrefix &&
		a.HostHeaderOverride == b.HostHeaderOverride && a.Comment == b.Comment && a.IsActive == b.IsActive
}

func statusOrDefault(code, fallback int) int64 {
	if code == 0 {
		return int64(fallback)
	}
	return int64(code)
}

func redirectStatus(code int) int {
	if control.IsValidRedirectStatus(code) {
		return code
	}
	return 302
}

func decodeStrings(raw string) []string {
	if raw == "" {
		return nil
	}
	var values []string
	_ = json.Unmarshal([]byte(raw), &values)
	return values
}
