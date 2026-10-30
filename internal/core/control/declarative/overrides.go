package declarative

import (
	"context"
	"encoding/json"
	"sort"
	"sync"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// OverrideSetting persists the identifiers that operators have taken ownership
// of through the control-plane API. Declarative sync skips these records so a
// dashboard edit is not silently reverted (or recreated) on the next deploy.
const OverrideSetting = "declarative_overrides"

// overrideMu serializes read-modify-write cycles on the override set inside a
// process. Cluster-wide writes are rare and last-writer-wins is acceptable for
// an ownership marker.
var overrideMu sync.Mutex

// LoadOverrides returns the set of declarative identifiers currently owned by
// the API. An unreadable or malformed setting yields an empty set: sync then
// falls back to normal YAML precedence instead of refusing to start.
func LoadOverrides(ctx context.Context, store control.ControlStore) map[string]struct{} {
	overrides := make(map[string]struct{})
	if store == nil {
		return overrides
	}
	raw, err := store.GetSetting(ctx, OverrideSetting)
	if err != nil || raw == "" {
		return overrides
	}

	var ids []string
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return overrides
	}
	for _, id := range ids {
		if IsManaged(id) {
			overrides[id] = struct{}{}
		}
	}
	return overrides
}

// Override records that id is now managed through the API. Non-declarative
// identifiers are ignored, so callers can pass every resource id they touch.
func Override(ctx context.Context, store control.ControlStore, id string) error {
	if store == nil || !IsManaged(id) {
		return nil
	}

	overrideMu.Lock()
	defer overrideMu.Unlock()

	overrides := LoadOverrides(ctx, store)
	if _, exists := overrides[id]; exists {
		return nil
	}
	overrides[id] = struct{}{}

	ids := make([]string, 0, len(overrides))
	for key := range overrides {
		ids = append(ids, key)
	}
	sort.Strings(ids)

	encoded, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return store.PutSetting(ctx, OverrideSetting, string(encoded))
}
