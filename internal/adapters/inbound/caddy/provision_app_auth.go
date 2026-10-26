package caddy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// appAuthSettingsKey persists the unified SSO clearance signing secret.
const appAuthSettingsKey = "app_auth_session_secret"

// resolveAppAuthSecret guarantees a stable portal-wide signing secret in
// raiwall_settings; first boot generates and persists one.
func (m *Middleware) resolveAppAuthSecret(ctx context.Context) (*string, error) {
	existing, err := m.controlStore.GetSetting(ctx, appAuthSettingsKey)
	if err == nil && existing != "" {
		return &existing, nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	secret := hex.EncodeToString(buf)
	if err := m.controlStore.PutSetting(ctx, appAuthSettingsKey, secret); err != nil {
		return nil, err
	}
	return &secret, nil
}

// buildGlobalAuthGate compiles the global `auth` block into the same HTTP
// 467 portal used by per-site gates. Called after the control store exists so
// stored identity providers can join the credential chain.
func (m *Middleware) buildGlobalAuthGate() {
	if m.AuthConfig == nil {
		return
	}

	providers := m.loadStoredIdentityProviders(context.Background())
	if m.globalAuthOIDC != nil {
		providers = appendUniqueProvider(providers, m.globalAuthOIDC)
	}

	opts := []auth.AppAuthGateOption{
		auth.WithBypassPaths(m.AuthConfig.BypassPaths...),
	}
	if m.globalAuthUsers != nil {
		opts = append(opts, auth.WithSimpleAuth(m.globalAuthUsers))
	}
	if len(providers) > 0 {
		opts = append(opts, auth.WithIdentityProviders(providers...))
	}
	if ttl := m.authSessionTTL(); ttl > 0 {
		opts = append(opts, auth.WithSessionTTL(ttl))
	}
	if m.AuthConfig.SessionSecure != nil {
		opts = append(opts, auth.WithSessionSecure(*m.AuthConfig.SessionSecure))
	}

	// One clearance secret for both gate modes. The persisted value is
	// authoritative so a cookie minted by the global gate is accepted by
	// per-site gates (and vice versa). The configured secret is only a
	// fallback when no control store is available.
	secret := ""
	if m.controlStore != nil {
		if persisted, err := m.resolveAppAuthSecret(context.Background()); err == nil {
			secret = *persisted
		}
	}
	if secret == "" {
		secret = m.AuthConfig.SessionSecret
	}
	if secret == "" && m.logger != nil {
		m.logger.Warn("auth block has no session_secret; using the built-in development secret")
	}

	m.globalAuthGate = auth.NewAppAuthGate(secret, m.directoryLoginLookup(), m.authAudit, opts...)
}

// loadStoredIdentityProviders compiles enabled external IdP connectors from
// the control store. Broken connectors are skipped, never fatal at boot.
func (m *Middleware) loadStoredIdentityProviders(ctx context.Context) []auth.IdentityProvider {
	if m.controlStore == nil {
		return nil
	}
	records, err := m.controlStore.ListIdentityProviders(ctx)
	if err != nil {
		if m.logger != nil {
			m.logger.Warn("failed to load identity providers", zap.Error(err))
		}
		return nil
	}

	providers := make([]auth.IdentityProvider, 0, len(records))
	for _, record := range records {
		if record.Enabled != 1 || record.Type == auth.ProviderTypeSimple {
			continue
		}
		provider, err := auth.NewIdentityProvider(auth.IdentityProviderSpec{
			Type:       record.Type,
			Name:       record.Name,
			ConfigJSON: record.Config,
		}, nil)
		if err != nil {
			if m.logger != nil {
				m.logger.Warn("skipping invalid identity provider",
					zap.String("provider", record.Name), zap.Error(err))
			}
			continue
		}
		providers = appendUniqueProvider(providers, provider)
	}
	return providers
}

// appendUniqueProvider avoids duplicate portal buttons for the same label.
func appendUniqueProvider(list []auth.IdentityProvider, provider auth.IdentityProvider) []auth.IdentityProvider {
	for _, existing := range list {
		if existing.Name() == provider.Name() {
			return list
		}
	}
	return append(list, provider)
}

// loadAppAuthGate wires the snapshot secret into a gate backed by the
// identity directory; returns nil when the site has no gate configuration.
func (m *Middleware) loadAppAuthGate(secret *string) *auth.AppAuthGate {
	if m.controlStore == nil || secret == nil || *secret == "" {
		return nil
	}

	opts := make([]auth.AppAuthGateOption, 0, 4)
	if m.globalAuthUsers != nil {
		opts = append(opts, auth.WithSimpleAuth(m.globalAuthUsers))
	}
	providers := m.loadStoredIdentityProviders(context.Background())
	if m.globalAuthOIDC != nil {
		providers = appendUniqueProvider(providers, m.globalAuthOIDC)
	}
	if len(providers) > 0 {
		opts = append(opts, auth.WithIdentityProviders(providers...))
	}

	return auth.NewAppAuthGate(*secret, m.directoryLoginLookup(), m.authAudit, opts...)
}

// directoryLoginLookup adapts the identity directory into the gate's login
// port. Shared by per-site and portal-wide gates so both modes authenticate
// the same directory accounts.
func (m *Middleware) directoryLoginLookup() auth.AppLoginStore {
	if m.controlStore == nil {
		return nil
	}
	return auth.DirectoryLookupFunc(func(ctx context.Context, username string) (*auth.AppLoginUser, error) {
		record, err := m.controlStore.GetIdentityUserByUsername(ctx, username)
		if err != nil {
			// Unknown usernames surface as nil (not an error) to the gate.
			return nil, nil
		}
		var apps []string
		_ = json.Unmarshal([]byte(record.AppIDs), &apps)
		return &auth.AppLoginUser{
			Username:       record.Username,
			PasswordHash:   record.PasswordHash,
			TOTPSecret:     record.TOTPSecret,
			TOTPEnrolled:   record.TOTPEnabled == 1,
			Enabled:        record.Enabled == 1,
			AuthorizedApps: apps,
		}, nil
	})
}

// authAudit persists one login attempt and mirrors failures into the live
// threat view.
func (m *Middleware) authAudit(event auth.LoginEvent) {
	if m.controlStore != nil {
		record := control.IdentityAuthEventRecord{
			Username: event.Username,
			AppID:    event.AppID,
			Host:     event.Host,
			Method:   event.Method,
			Result:   event.Result,
			ClientIP: event.ClientIP,
			Country:  event.Country,
			Detail:   event.Detail,
		}
		if err := m.controlStore.RecordIdentityAuthEvent(context.Background(), record); err != nil && m.logger != nil {
			m.logger.Warn("failed to persist auth audit event", zap.String("username", event.Username), zap.Error(err))
		}
	}
	// Failed attempts flow into the live threat view.
	if event.Result != auth.LoginResultSuccess {
		m.recordTelemetry(&telemetry.ForensicEvent{
			EventID:          uuid.NewString(),
			Host:             event.Host,
			Path:             auth.AppAuthLoginPath,
			Method:           http.MethodPost,
			ClientIP:         event.ClientIP,
			RuleID:           "auth_gate",
			MatchedToken:     event.Username,
			TruncatedPayload: event.Result + " · " + event.Detail,
			Action:           "block",
			Severity:         "medium",
			StatusCode:       auth.ChallengeStatusCode,
		})
	}
}
