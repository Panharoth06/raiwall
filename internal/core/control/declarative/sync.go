package declarative

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/config"
	"github.com/Panharoth06/raiwall/internal/core/control"
)

// SnapshotHashSetting records the content hash of the last declarative deploy
// so restarts with an unchanged file do not create a new snapshot version.
const SnapshotHashSetting = "declarative_snapshot_hash"

// Result summarizes what a sync pass changed.
type Result struct {
	Created  int
	Updated  int
	Deleted  int
	Skipped  int
	Warnings []string
}

// Changed reports whether the pass mutated any persisted record.
func (r Result) Changed() bool {
	return r.Created+r.Updated+r.Deleted > 0
}

type syncer struct {
	ctx       context.Context
	store     control.ControlStore
	mode      string
	prune     bool
	strict    bool
	overrides map[string]struct{}
	result    Result
}

// Sync upserts every declared resource into the control store. Strict mode
// returns an error on the first invalid or conflicting resource; lenient mode
// records a warning and continues.
func Sync(ctx context.Context, store control.ControlStore, res *config.DeclarativeResources) (Result, error) {
	if res == nil || res.Mode == "" || res.Mode == "off" {
		return Result{}, nil
	}
	if store == nil {
		return Result{}, fmt.Errorf("declarative sync requires a control store")
	}

	s := &syncer{
		ctx:       ctx,
		store:     store,
		mode:      res.Mode,
		prune:     res.Prune && res.Mode == "sync",
		strict:    res.Strict,
		overrides: LoadOverrides(ctx, store),
	}

	steps := []struct {
		kind string
		fn   func() error
	}{
		{KindCertificate, func() error { return s.syncCertificates(res.Certificates) }},
		{KindApplication, func() error { return s.syncApplications(res.Applications) }},
		{KindException, func() error { return s.syncExceptions(res.Exceptions) }},
		{KindACL, func() error { return s.syncACLs(res.ACLs) }},
		{KindIPGroup, func() error { return s.syncIPGroups(res.IPGroups) }},
		{KindRatePolicy, func() error { return s.syncRatePolicies(res.RatePolicies) }},
		{KindBotPolicy, func() error { return s.syncBotPolicies(res.BotPolicies) }},
		{KindIdentityProvider, func() error { return s.syncIdentityProviders(res.IdentityProviders) }},
		{KindTemplate, func() error { return s.syncTemplates(res.Templates) }},
		{"detector", func() error { return s.syncDetector(res.Detector) }},
	}

	for _, step := range steps {
		if err := step.fn(); err != nil {
			return s.result, fmt.Errorf("sync %s: %w", step.kind, err)
		}
	}

	return s.result, nil
}

// Apply compiles the current store into a snapshot and deploys it, unless the
// compiled content matches the last declarative deploy.
func Apply(ctx context.Context, store control.ControlStore) (bool, error) {
	if store == nil {
		return false, nil
	}

	snap, err := control.CompileSnapshot(ctx, store)
	if err != nil {
		return false, fmt.Errorf("compile declarative snapshot: %w", err)
	}
	hash, err := contentHash(snap)
	if err != nil {
		return false, err
	}

	previous, _ := store.GetSetting(ctx, SnapshotHashSetting)
	active := control.GetActiveSnapshot()
	if previous == hash && active != nil && active.Version > 0 {
		if activeHash, activeErr := contentHash(active); activeErr == nil && activeHash == hash {
			return false, nil
		}
	}

	deployed, err := control.DeploySnapshot(ctx, store, "declarative", "declarative configuration sync")
	if err != nil {
		return false, fmt.Errorf("deploy declarative snapshot: %w", err)
	}
	if err := store.PutSetting(ctx, SnapshotHashSetting, hash); err != nil {
		return true, fmt.Errorf("persist declarative snapshot hash: %w", err)
	}
	_ = deployed
	return true, nil
}

// contentHash ignores the snapshot version and timestamp so an unchanged
// configuration hashes identically across restarts.
func contentHash(snap *control.ConfigSnapshot) (string, error) {
	clone := *snap
	clone.Version = 0
	clone.CreatedAt = time.Time{}
	data, err := json.Marshal(&clone)
	if err != nil {
		return "", fmt.Errorf("hash snapshot: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// handle either aborts (strict) or records a skip warning (lenient).
func (s *syncer) handle(kind, name string, err error) error {
	if err == nil {
		return nil
	}
	wrapped := fmt.Errorf("%s %q: %w", kind, name, err)
	if s.strict {
		return wrapped
	}
	s.result.Skipped++
	s.result.Warnings = append(s.result.Warnings, wrapped.Error())
	return nil
}

// conflict reports a UI-managed record that already claims the natural key.
func (s *syncer) conflict(kind, key string) error {
	err := fmt.Errorf("%s %q is already managed through the API; remove it or rename the declarative resource", kind, key)
	if s.strict {
		return err
	}
	s.result.Skipped++
	s.result.Warnings = append(s.result.Warnings, err.Error())
	return nil
}

// canWrite reports whether an existing row may be modified in this pass.
func (s *syncer) canWrite(exists bool) bool {
	return s.mode == "sync" || !exists
}

// pruneIDs deletes managed records absent from the declared set.
func (s *syncer) pruneIDs(kind string, declared map[string]struct{}, existing []string, del func(string) error) error {
	if !s.prune {
		return nil
	}
	for _, id := range existing {
		if !IsManaged(id) {
			continue
		}
		if _, overridden := s.overrides[id]; overridden {
			continue
		}
		if _, keep := declared[id]; keep {
			continue
		}
		if err := del(id); err != nil {
			return err
		}
		s.result.Deleted++
		_ = kind
	}
	return nil
}
