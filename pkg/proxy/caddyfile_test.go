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
}
