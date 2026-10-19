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

func TestUnmarshalCaddyfile_Domain5AccessControl(t *testing.T) {
	input := `raiwall {
		mode defense
		exceptions {
			rule "allow_search_query" {
				host "example.com"
				path "/search"
				method "GET"
				location "query"
				param "q"
				rule_id "SEMANTIC_SQLI"
			}
			rule "allow_webhooks" {
				path_prefix "/webhooks/"
				method "POST"
				location "body"
				param "*"
				rule_id "*"
			}
		}

		acl {
			rule "block_high_risk" {
				expr "has_prefix(path, '/admin') && client_ip != '127.0.0.1'"
				action block
				priority 10
				status_code 403
			}
			rule "redirect_legacy" {
				expr "has_prefix(path, '/old')"
				action redirect
				priority 20
				status_code 302
				redirect_url "/new"
			}
		}

		auth {
			provider simple
			user admin "hashedPassword123" admin,ops
			session_secret "super-secure-session-secret-key-32b"
			session_ttl 12h
			session_cookie "rw_session"
			bypass_path /public/* /healthz
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	m := new(Middleware)
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	// Verify ExceptionConfig
	if m.ExceptionConfig == nil || len(m.ExceptionConfig.Rules) != 2 {
		t.Fatalf("expected 2 exception rules, got %v", m.ExceptionConfig)
	}
	r1 := m.ExceptionConfig.Rules[0]
	if r1.ID != "allow_search_query" || r1.Host != "example.com" || r1.ParamName != "q" || r1.RuleID != "SEMANTIC_SQLI" {
		t.Errorf("unexpected exception rule 1: %+v", r1)
	}
	r2 := m.ExceptionConfig.Rules[1]
	if r2.ID != "allow_webhooks" || r2.PathPrefix != "/webhooks/" || r2.RuleID != "*" {
		t.Errorf("unexpected exception rule 2: %+v", r2)
	}

	// Verify ACLConfig
	if m.ACLConfig == nil || len(m.ACLConfig.Rules) != 2 {
		t.Fatalf("expected 2 ACL rules, got %v", m.ACLConfig)
	}
	acl1 := m.ACLConfig.Rules[0]
	if acl1.Name != "block_high_risk" || acl1.Action != "block" || acl1.Priority != 10 || acl1.StatusCode != 403 {
		t.Errorf("unexpected ACL rule 1: %+v", acl1)
	}
	acl2 := m.ACLConfig.Rules[1]
	if acl2.Name != "redirect_legacy" || acl2.Action != "redirect" || acl2.RedirectURL != "/new" {
		t.Errorf("unexpected ACL rule 2: %+v", acl2)
	}

	// Verify AuthConfig
	if m.AuthConfig == nil {
		t.Fatal("expected AuthConfig to be populated")
	}
	if m.AuthConfig.Provider != "simple" {
		t.Errorf("expected provider 'simple', got %q", m.AuthConfig.Provider)
	}
	if len(m.AuthConfig.Users) != 1 || m.AuthConfig.Users[0].Username != "admin" {
		t.Errorf("unexpected users: %+v", m.AuthConfig.Users)
	}
	if len(m.AuthConfig.Users[0].Roles) != 2 || m.AuthConfig.Users[0].Roles[0] != "admin" || m.AuthConfig.Users[0].Roles[1] != "ops" {
		t.Errorf("unexpected user roles: %+v", m.AuthConfig.Users[0].Roles)
	}
	if m.AuthConfig.SessionSecret != "super-secure-session-secret-key-32b" {
		t.Errorf("unexpected session secret: %q", m.AuthConfig.SessionSecret)
	}
	if len(m.AuthConfig.BypassPaths) != 2 {
		t.Errorf("unexpected bypass paths: %+v", m.AuthConfig.BypassPaths)
	}

	// Test Provisioning
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := m.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision with Domain 5 configs failed: %v", err)
	}

	if m.ExceptionEngine() == nil {
		t.Fatal("expected ExceptionEngine to be provisioned")
	}
	if m.BARTTable() == nil {
		t.Fatal("expected BARTTable to be provisioned")
	}
	if m.ACLEngine() == nil {
		t.Fatal("expected ACLEngine to be provisioned")
	}
	if m.AuthGateway() == nil {
		t.Fatal("expected AuthGateway to be provisioned")
	}
}


func TestUnmarshalCaddyfile_AccessControlAndAuth(t *testing.T) {
	input := `raiwall {
		mode defense
		exceptions {
			rule EX_POST_MARKDOWN {
				host api.example.com
				path /api/v1/posts
				method POST
				location body
				param markdown_content
				rule_id SEMANTIC_SQLI
			}
		}
		acl {
			threat_feed spamhaus /tmp/spamhaus.txt
			geoip_db /tmp/GeoLite2-Country.mmdb
			geoip_asn /tmp/GeoLite2-ASN.mmdb
			rule block_threats {
				expr "in_feed(ip, 'spamhaus')"
				action block
				priority 10
				status_code 403
			}
			rule redirect_login {
				expr "path == '/old-login'"
				action redirect
				priority 20
				redirect_url /.raiwall/auth/login
			}
		}
		auth {
			provider simple
			user admin secretadmin admin,operator
			bypass_path /public/* /healthz
			session_secret my-super-secret-key-that-is-32-bytes
			session_cookie custom_session
			session_ttl 12h
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	m := new(Middleware)
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	// Verify exceptions
	if m.ExceptionConfig == nil || len(m.ExceptionConfig.Rules) != 1 {
		t.Fatalf("expected 1 exception rule, got %v", m.ExceptionConfig)
	}
	ex := m.ExceptionConfig.Rules[0]
	if ex.ID != "EX_POST_MARKDOWN" || ex.Host != "api.example.com" || ex.PathPrefix != "/api/v1/posts" ||
		ex.Method != "POST" || ex.Location != "body" || ex.ParamName != "markdown_content" || ex.RuleID != "SEMANTIC_SQLI" {
		t.Errorf("unexpected exception rule: %+v", ex)
	}

	// Verify ACL
	if m.ACLConfig == nil {
		t.Fatal("expected ACLConfig to be populated")
	}
	if m.ACLConfig.ThreatFeeds["spamhaus"] != "/tmp/spamhaus.txt" {
		t.Errorf("unexpected threat feed: %v", m.ACLConfig.ThreatFeeds)
	}
	if m.ACLConfig.GeoIPCountry != "/tmp/GeoLite2-Country.mmdb" {
		t.Errorf("unexpected GeoIPCountry: %s", m.ACLConfig.GeoIPCountry)
	}
	if m.ACLConfig.GeoIPASN != "/tmp/GeoLite2-ASN.mmdb" {
		t.Errorf("unexpected GeoIPASN: %s", m.ACLConfig.GeoIPASN)
	}
	if len(m.ACLConfig.Rules) != 2 {
		t.Fatalf("expected 2 ACL rules, got %d", len(m.ACLConfig.Rules))
	}
	if m.ACLConfig.Rules[0].Name != "block_threats" || m.ACLConfig.Rules[0].Action != "block" {
		t.Errorf("unexpected rule 0: %+v", m.ACLConfig.Rules[0])
	}
	if m.ACLConfig.Rules[1].Name != "redirect_login" || m.ACLConfig.Rules[1].Action != "redirect" || m.ACLConfig.Rules[1].RedirectURL != "/.raiwall/auth/login" {
		t.Errorf("unexpected rule 1: %+v", m.ACLConfig.Rules[1])
	}

	// Verify Auth
	if m.AuthConfig == nil {
		t.Fatal("expected AuthConfig to be populated")
	}
	if m.AuthConfig.Provider != "simple" {
		t.Errorf("expected provider simple, got %s", m.AuthConfig.Provider)
	}
	if len(m.AuthConfig.Users) != 1 || m.AuthConfig.Users[0].Username != "admin" {
		t.Errorf("unexpected users: %+v", m.AuthConfig.Users)
	}
	if len(m.AuthConfig.BypassPaths) != 2 || m.AuthConfig.BypassPaths[0] != "/public/*" {
		t.Errorf("unexpected bypass paths: %+v", m.AuthConfig.BypassPaths)
	}
	if m.AuthConfig.SessionCookie != "custom_session" {
		t.Errorf("unexpected session cookie: %s", m.AuthConfig.SessionCookie)
	}

	// Verify Provision
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := m.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	if m.ExceptionEngine() == nil {
		t.Fatal("expected ExceptionEngine to be provisioned")
	}
	if m.BARTTable() == nil {
		t.Fatal("expected BARTTable to be provisioned")
	}
	if m.ACLEngine() == nil {
		t.Fatal("expected ACLEngine to be provisioned")
	}
	if m.AuthGateway() == nil {
		t.Fatal("expected AuthGateway to be provisioned")
	}
	if m.GeoIPReader() == nil {
		t.Fatal("expected GeoIPReader to be provisioned")
	}

	defer func() { _ = m.Cleanup() }()
}

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

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
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

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
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



