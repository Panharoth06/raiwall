package declarative

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/config"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testStore(t *testing.T) *sqlite.Store {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", filepath.Join(t.TempDir(), "control.db"))
	store, err := sqlite.InitDB(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func sampleResources() *config.DeclarativeResources {
	return &config.DeclarativeResources{
		Mode: "sync",
		Applications: []config.Application{{
			Name:      "portal",
			Hostnames: []string{"app.example.com"},
			Mode:      "defense",
			Upstreams: []config.Upstream{{Dial: "127.0.0.1:9001"}},
			Forwarding: []config.ForwardingRule{{
				Prefix:      "/api",
				Upstreams:   []config.Upstream{{Dial: "127.0.0.1:9002"}},
				StripPrefix: true,
			}},
		}},
		ACLs: []config.ACLRule{{
			Name:       "block_bad_ip",
			Expression: "client_ip == '10.9.9.9'",
			Action:     "block",
			StatusCode: 403,
		}},
		Exceptions: []config.Exception{{
			Name:       "allow_search",
			Host:       "app.example.com",
			PathPrefix: "/search",
			ParamName:  "q",
			RuleID:     "SEMANTIC_SQLI",
		}},
		IPGroups: []config.IPGroup{{
			Name:        "corp",
			Description: "office ranges",
			Entries:     []config.IPGroupEntry{{CIDR: "10.0.0.0/8"}},
		}},
		RatePolicies: []config.RatePolicy{{
			Name:        "portal_rate",
			Host:        "app.example.com",
			Tier1Rate:   50,
			Tier1Burst:  10,
			Tier1Period: config.Duration(time.Second),
		}},
		BotPolicies: []config.BotPolicy{{
			Name:       "portal_bot",
			Host:       "app.example.com",
			PoWEnabled: true,
		}},
		IdentityProviders: []config.IdentityProvider{{
			Name: "corp_oidc",
			Type: "oidc",
			Config: map[string]any{
				"issuer_url": "https://idp.example.com",
				"client_id":  "raiwall",
			},
		}},
		Templates: []config.Template{{
			StatusCode:  403,
			Title:       "Blocked",
			ContentHTML: "<h1>Blocked</h1>",
		}},
		Detector: &config.Detector{
			Modules: map[string]string{"sql_inj": "strict"},
		},
	}
}

func TestSyncCreatesDeclaredResources(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	result, err := Sync(ctx, store, sampleResources())
	require.NoError(t, err)
	assert.Empty(t, result.Warnings)
	assert.Equal(t, 10, result.Created) // 9 named kinds + forwarding + IP group entry

	apps, err := store.ListApps(ctx)
	require.NoError(t, err)
	require.Len(t, apps, 1)
	assert.Equal(t, "cfg:app:portal", apps[0].ID)
	var upstreams []control.UpstreamTarget
	require.NoError(t, json.Unmarshal([]byte(apps[0].Upstreams), &upstreams))
	require.Len(t, upstreams, 1)
	assert.Equal(t, "127.0.0.1:9001", upstreams[0].Dial)

	rules, err := store.ListForwardingRulesByApp(ctx, apps[0].ID)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.True(t, IsManaged(rules[0].ID))
	assert.Equal(t, "/api", rules[0].Prefix)

	groups, err := store.ListIPGroups(ctx)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	entries, err := store.ListIPGroupEntries(ctx, groups[0].ID)
	require.NoError(t, err)
	assert.Len(t, entries, 1)

	detector, err := store.ListDetectorConfig(ctx)
	require.NoError(t, err)
	require.Len(t, detector, 1)
	assert.Equal(t, "sql_inj", detector[0].Module)
	assert.Equal(t, "strict", detector[0].Mode)

	// Second pass is a no-op.
	again, err := Sync(ctx, store, sampleResources())
	require.NoError(t, err)
	assert.Equal(t, 0, again.Created+again.Updated+again.Deleted)
}

func TestSyncSeedDoesNotUpdate(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	res := sampleResources()
	res.Mode = "seed"
	_, err := Sync(ctx, store, res)
	require.NoError(t, err)

	before, err := store.GetACLRule(ctx, "cfg:acl:block_bad_ip")
	require.NoError(t, err)

	res.ACLs[0].Expression = "client_ip == '10.1.1.1'"
	res.ACLs[0].StatusCode = 451
	_, err = Sync(ctx, store, res)
	require.NoError(t, err)

	after, err := store.GetACLRule(ctx, "cfg:acl:block_bad_ip")
	require.NoError(t, err)
	assert.Equal(t, before.Expression, after.Expression)
	assert.Equal(t, before.StatusCode, after.StatusCode)
}

func TestSyncSyncUpdatesInPlace(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	res := sampleResources()
	_, err := Sync(ctx, store, res)
	require.NoError(t, err)

	res.ACLs[0].Expression = "client_ip == '10.1.1.1'"
	result, err := Sync(ctx, store, res)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Updated)

	updated, err := store.GetACLRule(ctx, "cfg:acl:block_bad_ip")
	require.NoError(t, err)
	assert.Equal(t, "client_ip == '10.1.1.1'", updated.Expression)
}

func TestSyncPrunesStaleManagedRecords(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	res := sampleResources()
	res.Prune = true
	_, err := Sync(ctx, store, res)
	require.NoError(t, err)

	res.ACLs = nil
	res.Applications = nil
	result, err := Sync(ctx, store, res)
	require.NoError(t, err)
	assert.Positive(t, result.Deleted)

	rules, err := store.ListACLRules(ctx)
	require.NoError(t, err)
	assert.Empty(t, rules)
	apps, err := store.ListApps(ctx)
	require.NoError(t, err)
	assert.Empty(t, apps)
}

func TestSyncPruneKeepsUIManagedRecords(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	require.NoError(t, store.CreateACLRule(ctx, control.AclRule{
		ID: "manual-rule", Name: "manual", Expression: "true", Action: "audit",
		IsActive: 1, CreatedAt: now, UpdatedAt: now,
	}))

	res := sampleResources()
	res.Prune = true
	_, err := Sync(ctx, store, res)
	require.NoError(t, err)

	res.ACLs = nil
	_, err = Sync(ctx, store, res)
	require.NoError(t, err)

	rules, err := store.ListACLRules(ctx)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "manual-rule", rules[0].ID)
}

func TestSyncStrictConflictsWithUIManagedHostname(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	require.NoError(t, store.CreateApp(ctx, control.SiteApp{
		ID: "manual-app", Name: "manual", Hostnames: `["app.example.com"]`,
		Mode: "defense", Upstreams: `[{"dial":"127.0.0.1:9999"}]`,
		BlockStatusCode: 403, OfflineStatusCode: 503, SSLMode: "none",
		RoutingType: "proxy", LoadBalancing: "round_robin",
		CreatedAt: now, UpdatedAt: now,
	}))

	res := sampleResources()
	res.Strict = true
	_, err := Sync(ctx, store, res)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already managed through the API")

	res.Strict = false
	result, err := Sync(ctx, store, res)
	require.NoError(t, err)
	assert.NotEmpty(t, result.Warnings)
	assert.Positive(t, result.Skipped)
}

func TestApplyDeploysOnceAndSkipsUnchanged(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	_, err := Sync(ctx, store, sampleResources())
	require.NoError(t, err)

	deployed, err := Apply(ctx, store)
	require.NoError(t, err)
	assert.True(t, deployed)

	snapshots, err := store.ListSnapshots(ctx)
	require.NoError(t, err)
	require.Len(t, snapshots, 1)

	// An unchanged config must not create a second snapshot.
	deployed, err = Apply(ctx, store)
	require.NoError(t, err)
	assert.False(t, deployed)

	snapshots, err = store.ListSnapshots(ctx)
	require.NoError(t, err)
	assert.Len(t, snapshots, 1)
}

func TestSyncSelfSignedCertificateAndManualApp(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	res := &config.DeclarativeResources{
		Mode: "sync",
		Certificates: []config.Certificate{{
			Name:    "portal_cert",
			Domains: []string{"app.example.com"},
			Source:  "self-signed",
		}},
		Applications: []config.Application{{
			Name:        "portal",
			Hostnames:   []string{"app.example.com"},
			Mode:        "defense",
			Upstreams:   []config.Upstream{{Dial: "127.0.0.1:9001"}},
			SSLMode:     "manual",
			Certificate: "portal_cert",
			Ports:       []config.Port{{Port: 443, Scheme: "https"}},
		}},
	}
	_, err := Sync(ctx, store, res)
	require.NoError(t, err)

	certs, err := store.ListCertificates(ctx)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "cfg:certificate:portal_cert", certs[0].ID)
	assert.NotEmpty(t, certs[0].CertPEM)
	assert.NotEmpty(t, certs[0].EncryptedKeyPEM)
	assert.NotEmpty(t, certs[0].FingerprintSHA256)

	app, err := store.GetApp(ctx, "cfg:app:portal")
	require.NoError(t, err)
	assert.Equal(t, "cfg:certificate:portal_cert", app.CertificateID)
}

func TestSyncApplicationRequiresKnownCertificate(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	res := &config.DeclarativeResources{
		Mode: "sync",
		Applications: []config.Application{{
			Name:        "portal",
			Hostnames:   []string{"app.example.com"},
			Mode:        "defense",
			Upstreams:   []config.Upstream{{Dial: "127.0.0.1:9001"}},
			SSLMode:     "manual",
			Certificate: "missing",
		}},
	}

	_, err := Sync(ctx, store, res)
	require.NoError(t, err) // lenient: skip with warning
	apps, err := store.ListApps(ctx)
	require.NoError(t, err)
	assert.Empty(t, apps)
}

func TestSyncRejectsUnknownSemanticModule(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	res := &config.DeclarativeResources{
		Mode:   "sync",
		Strict: true,
		Applications: []config.Application{{
			Name:      "portal",
			Hostnames: []string{"app.example.com"},
			Mode:      "defense",
			Upstreams: []config.Upstream{{Dial: "127.0.0.1:9001"}},
			Semantic:  map[string]string{"not_a_module": "strict"},
		}},
	}
	_, err := Sync(ctx, store, res)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown semantic module")
}

func TestIsManaged(t *testing.T) {
	assert.True(t, IsManaged("cfg:app:portal"))
	assert.True(t, IsManaged(IDPrefix))
	assert.False(t, IsManaged("0c4f7e9a-1b2c-3d4e-5f60-718293a4b5c6"))
}
