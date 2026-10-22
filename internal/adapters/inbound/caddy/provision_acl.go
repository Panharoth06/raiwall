package caddy

import (
	"fmt"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/geoip"
	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

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
		countryPath := ""
		asnPath := ""
		if m.ACLConfig != nil {
			countryPath = m.ACLConfig.GeoIPCountry
			asnPath = m.ACLConfig.GeoIPASN
		}
		m.geoIPReader = geoip.NewGeoIPReaderOptional(countryPath, asnPath)
	}

	if m.ipGroupMgr == nil {
		m.ipGroupMgr = acl.NewIPGroupManager(m.bartTable)
	}

	if m.aclEngine == nil && m.ACLConfig != nil && len(m.ACLConfig.Rules) > 0 {
		aclEng, err := acl.NewACLEngine(m.bartTable, m.geoIPReader, m.ACLConfig.Rules...)
		if err != nil {
			return fmt.Errorf("provision acl engine: %w", err)
		}
		aclEng.SetIPGroupManager(m.ipGroupMgr)
		m.aclEngine = aclEng
	} else if m.aclEngine != nil {
		m.aclEngine.SetIPGroupManager(m.ipGroupMgr)
	}

	return nil
}
