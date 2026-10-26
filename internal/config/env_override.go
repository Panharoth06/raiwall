package config

import (
	"strconv"
	"strings"
)

// applyEnvOverrides applies the curated environment layer. Precedence is
// defaults < raiwall.yaml < environment, matching twelve-factor deployments
// where the file is the baseline and the platform injects secrets and ports.
func applyEnvOverrides(f *File) {
	if v, ok := lookupEnv("RAIWALL_HTTP_LISTEN"); ok {
		f.Server.HTTP.Listen = v
	}
	if v, ok := lookupEnv("RAIWALL_HTTPS_LISTEN"); ok {
		f.Server.HTTPS.Listen = v
	}
	if v, ok := lookupBool("RAIWALL_HTTP_ENABLED"); ok {
		f.Server.HTTP.Enabled = boolPtr(v)
	}
	if v, ok := lookupBool("RAIWALL_HTTPS_ENABLED"); ok {
		f.Server.HTTPS.Enabled = boolPtr(v)
	}
	if v, ok := lookupBool("RAIWALL_HTTP3"); ok {
		f.Server.HTTPS.HTTP3 = v
	}
	if v, ok := lookupEnv("RAIWALL_TLS_MIN_VERSION"); ok {
		f.Server.HTTPS.TLSMinVersion = v
	}
	if v, ok := lookupEnv("RAIWALL_LOG_LEVEL"); ok {
		f.Logging.Level = v
	}
	if v, ok := lookupEnv("RAIWALL_LOG_FORMAT"); ok {
		f.Logging.Format = v
	}
	if v, ok := lookupEnv("RAIWALL_CADDY_ADMIN"); ok {
		f.Caddy.Admin.Listen = v
	}
	if v, ok := lookupEnv("RAIWALL_CERTMAGIC_ROOT"); ok {
		f.Caddy.Storage.Root = v
	}

	applyStorageEnvOverrides(f)

	if v, ok := lookupEnv("RAIWALL_ADMIN_USERNAME"); ok {
		f.Control.BootstrapAdmin.Username = v
	}
	if v, ok := lookupEnv("RAIWALL_ADMIN_PASSWORD"); ok {
		f.Control.BootstrapAdmin.Password = v
	}
	if v, ok := lookupEnv("RAIWALL_HMAC_SECRET"); ok {
		f.Control.HMACSecret = v
	}
	if v, ok := lookupEnv("RAIWALL_POW_SECRET"); ok {
		f.Bot.PoWSecret = v
	}
	if f.Auth != nil {
		if v, ok := lookupEnv("RAIWALL_SESSION_SECRET"); ok {
			f.Auth.SessionSecret = v
		}
	}
	if f.Sidecar != nil {
		if v, ok := lookupEnv("RAIWALL_SIDECAR_LISTEN"); ok {
			f.Sidecar.Listen = v
		}
	}
	if v, ok := lookupEnv("RAIWALL_WAF_MODE"); ok {
		f.WAF.Mode = v
	}
}

func applyStorageEnvOverrides(f *File) {
	// Legacy deployments used DATABASE_URL for both roles.
	shared, hasShared := lookupEnv("DATABASE_URL")
	if v, ok := lookupEnv("RAIWALL_DATABASE_URL"); ok {
		shared, hasShared = v, true
	}

	if hasShared {
		if len(f.Storage.Stores) == 0 {
			f.Storage.DatabaseURL = shared
		} else {
			for name, store := range f.Storage.Stores {
				if name != f.Storage.Control && name != f.Storage.Telemetry {
					continue
				}
				store.DSN = shared
				store.Driver = driverFromDSN(shared)
				f.Storage.Stores[name] = store
			}
			if f.Storage.synthesizedFromDSN {
				f.Storage.DatabaseURL = shared
			}
		}
	}

	applyStoreEnv(f, "RAIWALL_CONTROL_DSN", f.Storage.Control)
	applyStoreEnv(f, "RAIWALL_TELEMETRY_DSN", f.Storage.Telemetry)
}

func applyStoreEnv(f *File, envVar, storeName string) {
	value, ok := lookupEnv(envVar)
	if !ok || storeName == "" {
		return
	}
	store, exists := f.Storage.Stores[storeName]
	if !exists {
		return
	}
	store.DSN = value
	store.Driver = driverFromDSN(value)
	f.Storage.Stores[storeName] = store
}

func lookupBool(name string) (bool, bool) {
	value, ok := lookupEnv(name)
	if !ok {
		return false, false
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return false, false
	}
	return parsed, true
}
