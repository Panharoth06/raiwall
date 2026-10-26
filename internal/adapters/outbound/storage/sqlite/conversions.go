package sqlite

import (
	"database/sql"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

func toControlSiteApp(r RaiwallApp) control.SiteApp {
	return control.SiteApp{
		ID:                  r.ID,
		Name:                r.Name,
		Hostnames:           r.Hostnames,
		Mode:                r.Mode,
		Upstreams:           r.Upstreams,
		BlockStatusCode:     r.BlockStatusCode,
		BlockResponseBody:   r.BlockResponseBody,
		OfflineStatusCode:   r.OfflineStatusCode,
		OfflineResponseBody: r.OfflineResponseBody,
		CustomHeaders:       r.CustomHeaders,
		ProxySettings:       r.ProxySettings,
		AuthEnabled:         r.AuthEnabled,
		AuthBypassPaths:     r.AuthBypassPaths,
		Description:         r.Description,
		Ports:               r.Ports,
		SSLMode:             r.SslMode,
		CertificateID:       r.CertificateID,
		RoutingType:         r.RoutingType,
		DocumentRoot:        r.DocumentRoot,
		RedirectURL:         r.RedirectUrl,
		RedirectStatus:      r.RedirectStatus,
		LoadBalancing:       r.LoadBalancing,
		CreatedAt:           r.CreatedAt,
		UpdatedAt:           r.UpdatedAt,
	}
}

func toControlExceptionRule(r RaiwallException) control.ExceptionRule {
	return control.ExceptionRule{
		ID:          r.ID,
		Description: r.Description,
		Host:        r.Host,
		PathRegex:   r.PathRegex,
		PathPrefix:  r.PathPrefix,
		Method:      r.Method,
		Location:    r.Location,
		ParamName:   r.ParamName,
		ParamRegex:  r.ParamRegex,
		RuleID:      r.RuleID,
		IsActive:    r.IsActive,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func toControlAclRule(r RaiwallAclRule) control.AclRule {
	return control.AclRule{
		ID:          r.ID,
		Name:        r.Name,
		Expression:  r.Expression,
		Action:      r.Action,
		Priority:    r.Priority,
		StatusCode:  r.StatusCode,
		RedirectUrl: r.RedirectUrl,
		IsActive:    r.IsActive,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func toControlRatePolicy(r RaiwallRatePolicy) control.RatePolicy {
	return control.RatePolicy{
		ID:                  r.ID,
		Name:                r.Name,
		Host:                r.Host,
		Tier1Rate:           r.Tier1Rate,
		Tier1Burst:          r.Tier1Burst,
		Tier1PeriodSec:      r.Tier1PeriodSec,
		Tier2Threshold:      r.Tier2Threshold,
		Tier2PeriodSec:      r.Tier2PeriodSec,
		Tier2BanDurationSec: r.Tier2BanDurationSec,
		Tier3Threshold:      r.Tier3Threshold,
		Tier3BanDurationSec: r.Tier3BanDurationSec,
		WaitingRoomEnabled:  r.WaitingRoomEnabled,
		WaitingRoomCapacity: r.WaitingRoomCapacity,
		WaitingRoomPaths:    r.WaitingRoomPaths,
		IsActive:            r.IsActive,
		CreatedAt:           r.CreatedAt,
		UpdatedAt:           r.UpdatedAt,
	}
}

func toControlBotConfig(r RaiwallBotConfig) control.BotConfig {
	return control.BotConfig{
		ID:            r.ID,
		Host:          r.Host,
		PowEnabled:    r.PowEnabled,
		PowDifficulty: r.PowDifficulty,
		TrapUrls:      r.TrapUrls,
		IsActive:      r.IsActive,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}
}

func toControlSnapshotRecord(r RaiwallConfigSnapshot) control.ConfigSnapshotRecord {
	return control.ConfigSnapshotRecord{
		Version:      r.Version,
		SnapshotData: r.SnapshotData,
		Author:       r.Author,
		Description:  r.Description,
		CreatedAt:    r.CreatedAt,
	}
}

func toControlUserRecord(r RaiwallUser) control.UserRecord {
	return control.UserRecord{
		ID:           r.ID,
		Username:     r.Username,
		PasswordHash: r.PasswordHash,
		Role:         r.Role,
		IsActive:     r.IsActive,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
	}
}

func toControlApiKeyRecord(r RaiwallApiKey) control.ApiKeyRecord {
	return control.ApiKeyRecord{
		ID:         r.ID,
		Name:       r.Name,
		KeyHash:    r.KeyHash,
		Role:       r.Role,
		ExpiresAt:  r.ExpiresAt,
		IsActive:   r.IsActive,
		CreatedAt:  r.CreatedAt,
		LastUsedAt: r.LastUsedAt,
	}
}

func toControlForwardingRule(r RaiwallForwardingRule) control.ForwardingRuleRecord {
	return control.ForwardingRuleRecord{
		ID:                 r.ID,
		AppID:              r.AppID,
		Prefix:             r.Prefix,
		Upstreams:          r.Upstreams,
		StripPrefix:        r.StripPrefix,
		HostHeaderOverride: r.HostHeaderOverride,
		Comment:            r.Comment,
		IsActive:           r.IsActive,
		CreatedAt:          r.CreatedAt,
		UpdatedAt:          r.UpdatedAt,
	}
}

func toControlApiResource(r RaiwallApiResource) control.ApiResourceRecord {
	return control.ApiResourceRecord{
		ID:          r.ID,
		AppID:       r.AppID,
		Method:      r.Method,
		PathPattern: r.PathPattern,
		ContentType: r.ContentType,
		HitCount:    r.HitCount,
		LastSeen:    r.LastSeen,
		CreatedAt:   r.CreatedAt,
	}
}

func toNullTime(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{Valid: false}
	}
	return sql.NullTime{Time: t, Valid: true}
}
