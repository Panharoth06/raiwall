package caddy

import (
	"context"
	"testing"

	caddyv2 "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

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
	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
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
	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
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
