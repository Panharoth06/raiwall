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

// loadAppAuthGateFor wires the snapshot secret into a gate backed by the
// identity directory; returns nil when the site has no gate configuration.
func (m *Middleware) loadAppAuthGate(secret *string) *auth.AppAuthGate {
	if m.controlStore == nil || secret == nil || *secret == "" {
		return nil
	}
	lookup := auth.DirectoryLookupFunc(func(ctx context.Context, username string) (*auth.AppLoginUser, error) {
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
	audit := func(event auth.LoginEvent) {
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
	return auth.NewAppAuthGate(*secret, lookup, audit)
}
