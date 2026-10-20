package caddy

import (
	"context"
	"testing"

	caddyv2 "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfile_SessionSecure(t *testing.T) {
	input := `raiwall {
		auth {
			provider simple
			user user1 pass123
			session_secret my-test-session-secret-that-is-32b
			session_secure false
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	m := new(Middleware)
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	if m.AuthConfig == nil || m.AuthConfig.SessionSecure == nil {
		t.Fatalf("expected SessionSecure to be parsed")
	}
	if *m.AuthConfig.SessionSecure != false {
		t.Errorf("expected SessionSecure false, got %v", *m.AuthConfig.SessionSecure)
	}

	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
	defer cancel()
	if err := m.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	defer func() { _ = m.Cleanup() }()
}

func TestUnmarshalCaddyfile_Telemetry(t *testing.T) {
	dbPath := "/tmp/test-caddy-telemetry-" + t.Name() + ".db"
	input := `raiwall {
		telemetry {
			storage sqlite ` + dbPath + `
			flush_interval 250ms
			buffer_size 5000
			retention 72h
			alert ops_slack https://hooks.slack.com/services/T00/B00/X00 {
				events block ban critical
				cooldown 2m
			}
			alert ops_discord https://discord.com/api/webhooks/123/abc {
				events critical
				cooldown 10m
			}
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	m := new(Middleware)
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	if m.TelemetryConfig == nil {
		t.Fatal("expected TelemetryConfig to be populated")
	}
	if m.TelemetryConfig.StorageType != "sqlite" {
		t.Errorf("expected storage type sqlite, got %s", m.TelemetryConfig.StorageType)
	}
	if m.TelemetryConfig.StoragePath != dbPath {
		t.Errorf("expected storage path %s, got %s", dbPath, m.TelemetryConfig.StoragePath)
	}
	if m.TelemetryConfig.BufferSize != 5000 {
		t.Errorf("expected buffer size 5000, got %d", m.TelemetryConfig.BufferSize)
	}
	if len(m.TelemetryConfig.AlertChannels) != 2 {
		t.Fatalf("expected 2 alert channels, got %d", len(m.TelemetryConfig.AlertChannels))
	}
	if m.TelemetryConfig.AlertChannels[0].Name != "ops_slack" {
		t.Errorf("unexpected alert channel 0 name: %s", m.TelemetryConfig.AlertChannels[0].Name)
	}
	if len(m.TelemetryConfig.AlertChannels[0].Events) != 3 {
		t.Errorf("unexpected alert channel 0 events: %v", m.TelemetryConfig.AlertChannels[0].Events)
	}

	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
	defer cancel()
	if err := m.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	defer func() {
		_ = m.Cleanup()
	}()

	if m.TelemetryStore() == nil {
		t.Error("expected TelemetryStore to be provisioned")
	}
	if m.RingBuffer() == nil {
		t.Error("expected RingBuffer to be provisioned")
	}
	if m.EventStreamer() == nil {
		t.Error("expected EventStreamer to be provisioned")
	}
	if m.AlertEngine() == nil {
		t.Error("expected AlertEngine to be provisioned")
	}
	if m.Metrics() == nil {
		t.Error("expected Metrics to be provisioned")
	}
	if m.UIHandler() == nil {
		t.Error("expected UIHandler to be provisioned")
	}
	if m.TelemetryAPI() == nil {
		t.Error("expected TelemetryAPI to be provisioned")
	}
}

func TestUnmarshalCaddyfile_Sidecar(t *testing.T) {
	input := `raiwall {
		sidecar {
			listen :50051
			max_body_size 2MB
		}
	}`
	d := caddyfile.NewTestDispenser(input)
	m := new(Middleware)
	err := m.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	if m.SidecarConfig == nil {
		t.Fatal("expected SidecarConfig to be non-nil")
	}
	if m.SidecarConfig.Listen != ":50051" {
		t.Errorf("expected listen :50051, got %s", m.SidecarConfig.Listen)
	}
	if m.SidecarConfig.MaxBodySize != 2*1024*1024 {
		t.Errorf("expected max_body_size 2MB (%d), got %d", 2*1024*1024, m.SidecarConfig.MaxBodySize)
	}
}

func TestUnmarshalCaddyfile_Control(t *testing.T) {
	input := `raiwall {
		control {
			db_path "file:custom_control.db"
			hmac_secret "custom-secret-key-32-chars-long"
		}
	}`
	d := caddyfile.NewTestDispenser(input)
	m := new(Middleware)
	err := m.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	if m.ControlConfig == nil {
		t.Fatal("expected ControlConfig to be non-nil")
	}
	if m.ControlConfig.DBPath != "file:custom_control.db" {
		t.Errorf("expected db_path file:custom_control.db, got %s", m.ControlConfig.DBPath)
	}
	if m.ControlConfig.HMACSecret != "custom-secret-key-32-chars-long" {
		t.Errorf("expected hmac_secret custom-secret-key-32-chars-long, got %s", m.ControlConfig.HMACSecret)
	}
}
