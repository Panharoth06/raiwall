package proxy

import (
	"context"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedMode  string
		expectedBlock int
		expectedOff   int
		expectedStrip []string
		wantErr       bool
	}{
		{
			name:          "positional argument mode",
			input:         `raiwall defense`,
			expectedMode:  "defense",
			expectedBlock: 0, // default untouched before Provision
			expectedOff:   0,
			wantErr:       false,
		},
		{
			name: "full block configuration",
			input: `raiwall {
				mode audit
				block_status 401
				offline_status 504
				strip_headers Server X-Powered-By X-Custom
			}`,
			expectedMode:  "audit",
			expectedBlock: 401,
			expectedOff:   504,
			expectedStrip: []string{"Server", "X-Powered-By", "X-Custom"},
			wantErr:       false,
		},
		{
			name: "positional mode with block override",
			input: `raiwall defense {
				mode offline
			}`,
			expectedMode: "offline",
			wantErr:      false,
		},
		{
			name: "invalid block_status not a number",
			input: `raiwall {
				block_status notanumber
			}`,
			wantErr: true,
		},
		{
			name: "block_status out of range high",
			input: `raiwall {
				block_status 9999
			}`,
			wantErr: true,
		},
		{
			name: "block_status out of range low",
			input: `raiwall {
				block_status 150
			}`,
			wantErr: true,
		},
		{
			name: "invalid offline_status not a number",
			input: `raiwall {
				offline_status badcode
			}`,
			wantErr: true,
		},
		{
			name: "offline_status out of range low",
			input: `raiwall {
				offline_status 80
			}`,
			wantErr: true,
		},
		{
			name: "positional mode with extra arguments",
			input: `raiwall defense extra_arg {
			}`,
			wantErr: true,
		},
		{
			name: "mode directive with extra arguments",
			input: `raiwall {
				mode defense extra_arg
			}`,
			wantErr: true,
		},
		{
			name: "ast_timeout and max_param_size valid",
			input: `raiwall {
				ast_timeout 15ms
				max_param_size 65536
			}`,
			wantErr: false,
		},
		{
			name: "invalid ast_timeout format",
			input: `raiwall {
				ast_timeout invalid_duration
			}`,
			wantErr: true,
		},
		{
			name: "invalid max_param_size negative",
			input: `raiwall {
				max_param_size -50
			}`,
			wantErr: true,
		},
		{
			name: "invalid max_param_size not a number",
			input: `raiwall {
				max_param_size notanumber
			}`,
			wantErr: true,
		},
		{
			name: "valid bot defense configuration",
			input: `raiwall {
				bot_defense defense
				pow_difficulty 60000
				clearance_ttl 3h
				honeypot true
			}`,
			expectedMode: "",
			wantErr:      false,
		},
		{
			name: "invalid bot_defense mode",
			input: `raiwall {
				bot_defense invalid_mode
			}`,
			wantErr: true,
		},
		{
			name: "invalid pow_difficulty not a number",
			input: `raiwall {
				pow_difficulty bad
			}`,
			wantErr: true,
		},
		{
			name: "invalid clearance_ttl duration",
			input: `raiwall {
				clearance_ttl notaduration
			}`,
			wantErr: true,
		},
		{
			name: "invalid honeypot boolean",
			input: `raiwall {
				honeypot invalid_bool
			}`,
			wantErr: true,
		},
		{
			name: "unrecognized subdirective",
			input: `raiwall {
				unknown_param foo
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			m := new(Middleware)
			err := m.UnmarshalCaddyfile(d)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if m.Mode != tt.expectedMode {
				t.Errorf("Mode = %q, want %q", m.Mode, tt.expectedMode)
			}
			if tt.expectedBlock != 0 && m.BlockStatusCode != tt.expectedBlock {
				t.Errorf("BlockStatusCode = %d, want %d", m.BlockStatusCode, tt.expectedBlock)
			}
			if tt.expectedOff != 0 && m.OfflineStatusCode != tt.expectedOff {
				t.Errorf("OfflineStatusCode = %d, want %d", m.OfflineStatusCode, tt.expectedOff)
			}
			if len(tt.expectedStrip) > 0 {
				if len(m.StripHeaders) != len(tt.expectedStrip) {
					t.Errorf("StripHeaders len = %d, want %d", len(m.StripHeaders), len(tt.expectedStrip))
				}
			}
		})
	}
}

func TestMiddlewareProvision_SemanticEngineDefault(t *testing.T) {
	m := &Middleware{
		Mode: "defense",
	}
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	if err := m.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	if m.engine == nil {
		t.Fatal("expected m.engine to be provisioned, got nil")
	}

	if m.engine.Name() != "semantic" {
		t.Errorf("expected engine name 'semantic', got %q", m.engine.Name())
	}

	if m.PoWEngine() == nil {
		t.Fatal("expected m.powEngine to be provisioned, got nil")
	}
	if m.ClearanceManager() == nil {
		t.Fatal("expected m.clearanceMgr to be provisioned, got nil")
	}
	if m.TrapController() == nil {
		t.Fatal("expected m.trapCtrl to be provisioned, got nil")
	}
	if m.BanManager() == nil {
		t.Fatal("expected m.banManager to be provisioned, got nil")
	}
}

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
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
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
