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

func TestStore_IPGroupsAndTemplates(t *testing.T) {
	ctx := context.Background()
	dsn := "file:test_phase7_" + uuid.New().String() + ".db?mode=memory"
	store, err := InitDB(dsn)
	require.NoError(t, err)
	defer store.Close()

	// 1. IP Group CRUD
	grp := control.IPGroupRecord{
		ID:          uuid.New().String(),
		Name:        "trusted_proxies",
		Description: "Internal proxies",
		Type:        "custom",
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}

	err = store.CreateIPGroup(ctx, grp)
	require.NoError(t, err)

	fetched, err := store.GetIPGroup(ctx, grp.ID)
	require.NoError(t, err)
	assert.Equal(t, grp.Name, fetched.Name)

	byName, err := store.GetIPGroupByName(ctx, "trusted_proxies")
	require.NoError(t, err)
	assert.Equal(t, grp.ID, byName.ID)

	// Add entry
	entry := control.IPGroupEntryRecord{
		ID:        uuid.New().String(),
		GroupID:   grp.ID,
		CIDR:      "10.0.0.0/16",
		Comment:   "Main VPC",
		CreatedAt: time.Now().UTC(),
	}
	err = store.CreateIPGroupEntry(ctx, entry)
	require.NoError(t, err)

	entries, err := store.ListIPGroupEntries(ctx, grp.ID)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "10.0.0.0/16", entries[0].CIDR)

	// Delete entry
	err = store.DeleteIPGroupEntry(ctx, entry.ID)
	require.NoError(t, err)
	entriesAfter, err := store.ListIPGroupEntries(ctx, grp.ID)
	require.NoError(t, err)
	assert.Len(t, entriesAfter, 0)

	// Delete group
	err = store.DeleteIPGroup(ctx, grp.ID)
	require.NoError(t, err)
	_, err = store.GetIPGroup(ctx, grp.ID)
	assert.Error(t, err)

	// 2. Templates CRUD
	tmpl := control.TemplateRecord{
		ID:          uuid.New().String(),
		StatusCode:  403,
		Title:       "Access Forbidden",
		ContentHTML: "<h1>Forbidden</h1>",
		CustomCSS:   "h1 { color: red; }",
		BrandName:   "Acme Corp",
		LogoURL:     "https://example.com/logo.png",
		IsCustom:    1,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	err = store.UpsertTemplate(ctx, tmpl)
	require.NoError(t, err)

	fetchedTmpl, err := store.GetTemplate(ctx, 403)
	require.NoError(t, err)
	assert.Equal(t, "Access Forbidden", fetchedTmpl.Title)
	assert.Equal(t, "Acme Corp", fetchedTmpl.BrandName)

	listTmpls, err := store.ListTemplates(ctx)
	require.NoError(t, err)
	assert.Len(t, listTmpls, 1)

	// Delete template
	err = store.DeleteTemplate(ctx, 403)
	require.NoError(t, err)
	_, err = store.GetTemplate(ctx, 403)
	assert.Error(t, err)
}
