package sqlite

import (
	"database/sql"
	"fmt"
	"strings"
)

// additiveUpgrades keeps databases bootstrapped from an older schema.sql in
// sync with the current schema. schema.sql is idempotent for tables, but
// SQLite has no ADD COLUMN IF NOT EXISTS, so duplicate-column errors are
// expected and ignored on already-upgraded databases.
var additiveUpgrades = []string{
	`ALTER TABLE raiwall_apps ADD COLUMN description TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE raiwall_apps ADD COLUMN ports TEXT NOT NULL DEFAULT '[{"port":80,"scheme":"http"}]'`,
	`ALTER TABLE raiwall_apps ADD COLUMN ssl_mode TEXT NOT NULL DEFAULT 'none'`,
	`ALTER TABLE raiwall_apps ADD COLUMN certificate_id TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE raiwall_apps ADD COLUMN routing_type TEXT NOT NULL DEFAULT 'proxy'`,
	`ALTER TABLE raiwall_apps ADD COLUMN document_root TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE raiwall_apps ADD COLUMN redirect_url TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE raiwall_apps ADD COLUMN redirect_status INTEGER NOT NULL DEFAULT 302`,
	`ALTER TABLE raiwall_apps ADD COLUMN load_balancing TEXT NOT NULL DEFAULT 'round_robin'`,
}

// applyAdditiveUpgrades upgrades legacy databases in place.
func applyAdditiveUpgrades(db *sql.DB) error {
	for _, stmt := range additiveUpgrades {
		if _, err := db.Exec(stmt); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
				continue
			}
			return fmt.Errorf("apply schema upgrade %q: %w", stmt, err)
		}
	}
	return nil
}
