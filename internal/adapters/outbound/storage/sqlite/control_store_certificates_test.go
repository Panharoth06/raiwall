package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_CertificateCRUD(t *testing.T) {
	ctx := context.Background()
	store, err := InitDB("file:test_certs_" + uuid.New().String() + ".db?mode=memory")
	require.NoError(t, err)
	defer store.Close()

	// Empty store.
	records, err := store.ListCertificates(ctx)
	require.NoError(t, err)
	require.Empty(t, records)

	now := time.Now().UTC().Truncate(time.Second)
	record := control.CertificateRecord{
		ID:                "cert-1",
		Name:              "primary",
		Domains:           `["app.example.com"]`,
		Source:            control.CertSourceSelfSigned,
		CertPEM:           "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		EncryptedKeyPEM:   "sealed-key",
		FingerprintSHA256: "abc123",
		Issuer:            "Raiwall Self-Signed",
		NotBefore:         now,
		NotAfter:          now.Add(90 * 24 * time.Hour),
		AutoRenew:         1,
		LastError:         "",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	require.NoError(t, store.CreateCertificate(ctx, record))

	got, err := store.GetCertificate(ctx, "cert-1")
	require.NoError(t, err)
	assert.Equal(t, record.Name, got.Name)
	assert.Equal(t, record.Domains, got.Domains)
	assert.Equal(t, record.Source, got.Source)
	assert.Equal(t, record.EncryptedKeyPEM, got.EncryptedKeyPEM)
	assert.Equal(t, record.FingerprintSHA256, got.FingerprintSHA256)
	assert.WithinDuration(t, record.NotAfter, got.NotAfter, time.Second)
	assert.EqualValues(t, 1, got.AutoRenew)

	// Update fields.
	updated := got
	updated.Name = "renamed"
	updated.LastError = "acme: dns not reachable"
	updated.AutoRenew = 0
	updated.UpdatedAt = now.Add(time.Minute)
	require.NoError(t, store.UpdateCertificate(ctx, updated))

	got, err = store.GetCertificate(ctx, "cert-1")
	require.NoError(t, err)
	assert.Equal(t, "renamed", got.Name)
	assert.Equal(t, "acme: dns not reachable", got.LastError)
	assert.EqualValues(t, 0, got.AutoRenew)

	// Second record ordering (by name).
	require.NoError(t, store.CreateCertificate(ctx, control.CertificateRecord{
		ID: "cert-2", Name: "aaa-wildcard", Domains: `["*.example.com"]`,
		Source: control.CertSourceACME, AutoRenew: 1, CreatedAt: now, UpdatedAt: now,
	}))
	records, err = store.ListCertificates(ctx)
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, "aaa-wildcard", records[0].Name)
	assert.Equal(t, "renamed", records[1].Name)

	// Delete.
	require.NoError(t, store.DeleteCertificate(ctx, "cert-1"))
	_, err = store.GetCertificate(ctx, "cert-1")
	require.Error(t, err)
}

func TestStore_AppRoutingColumnsRoundTrip(t *testing.T) {
	ctx := context.Background()
	store, err := InitDB("file:test_app_routing_" + uuid.New().String() + ".db?mode=memory")
	require.NoError(t, err)
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second)
	app := control.SiteApp{
		ID:              "site-1",
		Name:            "Static Site",
		Hostnames:       `["static.example.com"]`,
		Mode:            string(control.ModeDefense),
		Upstreams:       `[]`,
		BlockStatusCode: 403,
		CustomHeaders:   `{}`,
		ProxySettings:   "",
		AuthBypassPaths: `[]`,
		Description:     "serves a marketing bundle",
		Ports:           `[{"port":80,"scheme":"http"},{"port":443,"scheme":"https"}]`,
		SSLMode:         control.SSLModeAuto,
		CertificateID:   "",
		RoutingType:     control.RoutingStatic,
		DocumentRoot:    "/srv/www",
		RedirectURL:     "",
		RedirectStatus:  302,
		LoadBalancing:   control.LoadBalanceLeastConn,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	require.NoError(t, store.CreateApp(ctx, app))

	got, err := store.GetApp(ctx, "site-1")
	require.NoError(t, err)
	assert.Equal(t, app.Description, got.Description)
	assert.Equal(t, app.Ports, got.Ports)
	assert.Equal(t, app.SSLMode, got.SSLMode)
	assert.Equal(t, app.RoutingType, got.RoutingType)
	assert.Equal(t, app.DocumentRoot, got.DocumentRoot)
	assert.EqualValues(t, 302, got.RedirectStatus)
	assert.Equal(t, app.LoadBalancing, got.LoadBalancing)

	app.RoutingType = control.RoutingRedirect
	app.RedirectURL = "https://example.com"
	app.RedirectStatus = 308
	app.UpdatedAt = now.Add(time.Minute)
	require.NoError(t, store.UpdateApp(ctx, app))

	got, err = store.GetApp(ctx, "site-1")
	require.NoError(t, err)
	assert.Equal(t, control.RoutingRedirect, got.RoutingType)
	assert.Equal(t, "https://example.com", got.RedirectURL)
	assert.EqualValues(t, 308, got.RedirectStatus)

	apps, err := store.ListApps(ctx)
	require.NoError(t, err)
	require.Len(t, apps, 1)
	assert.Equal(t, control.RoutingRedirect, apps[0].RoutingType)
}
