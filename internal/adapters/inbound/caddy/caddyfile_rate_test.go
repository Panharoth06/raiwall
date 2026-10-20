package caddy

import (
	"context"
	"testing"

	caddyv2 "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfile_RateLimitAndWaitingRoom(t *testing.T) {
	input := `raiwall {
		rate_limit {
			tier1_velocity 100 10s 20
			tier2_attack 10 60s 24h
			tier3_scanner 20 30s 24h
			storage redis 127.0.0.1:6379
		}
		waiting_room {
			max_concurrent 500
			max_queue_depth 1000
			admission_rate 50
			token_ttl 15m
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	m := new(Middleware)
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	if m.RateLimitConfig == nil {
		t.Fatal("expected RateLimitConfig to be populated")
	}
	if m.RateLimitConfig.Tier1Rate != 100 {
		t.Errorf("expected Tier1Rate 100, got %d", m.RateLimitConfig.Tier1Rate)
	}
	if m.RateLimitConfig.Tier1Burst != 20 {
		t.Errorf("expected Tier1Burst 20, got %d", m.RateLimitConfig.Tier1Burst)
	}
	if m.RateLimitConfig.Tier2Threshold != 10 {
		t.Errorf("expected Tier2Threshold 10, got %d", m.RateLimitConfig.Tier2Threshold)
	}
	if m.RateLimitConfig.Tier3Threshold != 20 {
		t.Errorf("expected Tier3Threshold 20, got %d", m.RateLimitConfig.Tier3Threshold)
	}
	if m.RateLimitConfig.StorageType != "redis" || m.RateLimitConfig.StorageAddr != "127.0.0.1:6379" {
		t.Errorf("unexpected storage config: %s %s", m.RateLimitConfig.StorageType, m.RateLimitConfig.StorageAddr)
	}

	if m.WaitingRoomConfig == nil {
		t.Fatal("expected WaitingRoomConfig to be populated")
	}
	if !m.WaitingRoomConfig.Enabled {
		t.Errorf("expected WaitingRoomConfig.Enabled = true")
	}
	if m.WaitingRoomConfig.MaxConcurrentInFlight != 500 {
		t.Errorf("expected MaxConcurrentInFlight 500, got %d", m.WaitingRoomConfig.MaxConcurrentInFlight)
	}
	if m.WaitingRoomConfig.MaxQueueDepth != 1000 {
		t.Errorf("expected MaxQueueDepth 1000, got %d", m.WaitingRoomConfig.MaxQueueDepth)
	}
	if m.WaitingRoomConfig.AdmissionRate != 50 {
		t.Errorf("expected AdmissionRate 50, got %d", m.WaitingRoomConfig.AdmissionRate)
	}

	// Test Provision with populated configs
	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
	defer cancel()
	if err := m.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision with rate_limit and waiting_room failed: %v", err)
	}

	if m.Tier1Limiter() == nil {
		t.Fatal("expected Tier1Limiter to be provisioned")
	}
	if m.Tier2Limiter() == nil {
		t.Fatal("expected Tier2Limiter to be provisioned")
	}
	if m.Tier3Trap() == nil {
		t.Fatal("expected Tier3Trap to be provisioned")
	}
	if m.WaitingRoom() == nil {
		t.Fatal("expected WaitingRoom to be provisioned")
	}
}
