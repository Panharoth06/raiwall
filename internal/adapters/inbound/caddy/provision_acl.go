package caddy

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/http"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/geoip"
	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// geoIPUpdateTimeout bounds the startup refresh so an unreachable MaxMind
// endpoint can never stall the gateway indefinitely.
const geoIPUpdateTimeout = 60 * time.Second

func (m *Middleware) provisionACL(_ caddy.Context) error {
	if m.bartTable == nil {
		m.bartTable = acl.NewBARTTable()
		if m.ACLConfig != nil && len(m.ACLConfig.ThreatFeeds) > 0 {
			for name, path := range m.ACLConfig.ThreatFeeds {
				_, err := acl.LoadFeedFile(path, name, m.bartTable)
				if err != nil && m.logger != nil {
					m.logger.Warn("Failed to load threat feed", zap.String("feed", name), zap.String("path", path), zap.Error(err))
				}
			}
		}
	}

	if m.geoIPReader == nil {
		cfg := geoIPConfig(m.ACLConfig)
		if m.ACLConfig != nil && m.ACLConfig.GeoIPAutoUpdate {
			m.refreshGeoIPDatabases(cfg)
		}
		reader, err := geoip.NewGeoIPReader(m.existingGeoIPConfig(cfg))
		if err != nil {
			// Geo enrichment is optional: log the cause so a misconfigured path
			// is diagnosable, then keep serving without geo data.
			m.logWarn("GeoIP databases unavailable", zap.Error(err))
			reader = geoip.NewNoopGeoIPReader()
		}
		m.geoIPReader = reader
	}

	if m.ipGroupMgr == nil {
		m.ipGroupMgr = acl.NewIPGroupManager(m.bartTable)
	}

	if eng := m.aclEngine.Load(); eng == nil {
		if m.ACLConfig != nil && len(m.ACLConfig.Rules) > 0 {
			aclEng, err := acl.NewACLEngine(m.bartTable, m.geoIPReader, m.ACLConfig.Rules...)
			if err != nil {
				return fmt.Errorf("provision acl engine: %w", err)
			}
			aclEng.SetIPGroupManager(m.ipGroupMgr)
			m.SetACLEngine(aclEng)
		}
	} else {
		eng.SetIPGroupManager(m.ipGroupMgr)
	}

	m.geoipAPI = api.NewGeoIPStatusAPI(m.geoIPStatus)
	return nil
}

// existingGeoIPConfig drops configured database paths that are not present on
// disk, logging each one. Operators commonly mount only the editions they need
// (for example a single City database that also supplies country data), so a
// missing sibling edition must not disable the whole lookup.
func (m *Middleware) existingGeoIPConfig(cfg geoip.Config) geoip.Config {
	present := func(label, path string) string {
		if path == "" {
			return ""
		}
		if _, err := os.Stat(path); err != nil {
			m.logWarn("GeoIP database missing",
				zap.String("database", label), zap.String("path", path))
			return ""
		}
		return path
	}
	return geoip.Config{
		CountryPath: present("country", cfg.CountryPath),
		CityPath:    present("city", cfg.CityPath),
		ASNPath:     present("asn", cfg.ASNPath),
	}
}

// geoIPConfig projects the runtime ACL settings onto the GeoIP adapter config.
func geoIPConfig(settings *ACLSettings) geoip.Config {
	if settings == nil {
		return geoip.Config{}
	}
	return geoip.Config{
		CountryPath: settings.GeoIPCountry,
		CityPath:    settings.GeoIPCity,
		ASNPath:     settings.GeoIPASN,
	}
}

// refreshGeoIPDatabases downloads missing or stale MaxMind editions. Failures
// are logged instead of aborting startup: the gateway keeps serving without
// geo enrichment rather than refusing to boot on a network problem.
func (m *Middleware) refreshGeoIPDatabases(cfg geoip.Config) {
	licenseKey := geoIPLicenseKey()
	if licenseKey == "" {
		m.logInfo("GeoIP auto_update is enabled but RAIWALL_GEOIP_LICENSE_KEY is not set; skipping download")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), geoIPUpdateTimeout)
	defer cancel()

	refreshed, err := geoip.EnsureDatabases(ctx, licenseKey,
		geoip.Database{Edition: "GeoLite2-Country", Path: cfg.CountryPath},
		geoip.Database{Edition: "GeoLite2-City", Path: cfg.CityPath},
		geoip.Database{Edition: "GeoLite2-ASN", Path: cfg.ASNPath},
	)
	if len(refreshed) > 0 {
		m.logInfo("GeoIP databases refreshed", zap.Strings("editions", refreshed))
	}
	if err != nil {
		m.logWarn("GeoIP database refresh failed", zap.Error(err))
	}
}

// geoIPLicenseKey resolves the MaxMind download credential from the environment,
// supporting the _FILE convention used for container secrets.
func geoIPLicenseKey() string {
	if value := strings.TrimSpace(os.Getenv("RAIWALL_GEOIP_LICENSE_KEY")); value != "" {
		return value
	}
	if path := strings.TrimSpace(os.Getenv("RAIWALL_GEOIP_LICENSE_KEY_FILE")); path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

// geoIPStatus reports which MaxMind databases are currently loaded.
func (m *Middleware) geoIPStatus() api.GeoIPStatus {
	reader, ok := m.geoIPReader.(interface {
		HasCountryDB() bool
		HasCityDB() bool
		HasASNDB() bool
	})
	if !ok {
		return api.GeoIPStatus{}
	}
	return api.GeoIPStatus{
		CountryDB: reader.HasCountryDB(),
		CityDB:    reader.HasCityDB(),
		ASNDB:     reader.HasASNDB(),
	}
}

func (m *Middleware) logInfo(msg string, fields ...zap.Field) {
	if m.logger != nil {
		m.logger.Info(msg, fields...)
	}
}

func (m *Middleware) logWarn(msg string, fields ...zap.Field) {
	if m.logger != nil {
		m.logger.Warn(msg, fields...)
	}
}
