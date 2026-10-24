package api

import (
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

func TestGlobalBotConfigSelectsWildcardPolicy(t *testing.T) {
	hostOverride := control.BotConfig{ID: "bot-host", Host: "app.example.com"}
	global := control.BotConfig{ID: "bot-global", Host: "*"}

	tests := []struct {
		name    string
		configs []control.BotConfig
		wantID  string
	}{
		{name: "no configs", configs: nil, wantID: ""},
		{name: "only host overrides", configs: []control.BotConfig{hostOverride}, wantID: ""},
		{
			name:    "host override listed first",
			configs: []control.BotConfig{hostOverride, global},
			wantID:  "bot-global",
		},
		{
			name:    "wildcard listed first",
			configs: []control.BotConfig{global, hostOverride},
			wantID:  "bot-global",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := globalBotConfig(tt.configs)
			if tt.wantID == "" {
				if got != nil {
					t.Fatalf("expected nil config, got %q", got.ID)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected config %q, got nil", tt.wantID)
			}
			if got.ID != tt.wantID {
				t.Fatalf("expected config %q, got %q", tt.wantID, got.ID)
			}
		})
	}
}
