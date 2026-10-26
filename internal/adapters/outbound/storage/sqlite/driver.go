package sqlite

// Blank import registers the pure-Go "sqlite" database/sql driver backed by
// modernc.org/sqlite. Both the control and telemetry stores open it by name,
// so persistence is real (no CGO, no in-process stand-in).

import (
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

// legacyStubSize is the exact byte length of the file the retired in-memory
// driver wrote: the 16-byte SQLite magic header with no pages behind it.
const legacyStubSize = 16

const sqliteMagic = "SQLite format 3\x00"

// PrepareDSN applies upgrade safeguards before opening a SQLite pool.
func PrepareDSN(dsn string) error {
	return prepareSQLiteDSN(dsn)
}

// prepareSQLiteDSN quarantines a leftover magic-only stub so real SQLite can
// create a valid database in its place. Databases with real pages are never
// touched; names that do not map to a file (":memory:", shared-memory URIs)
// are ignored.
func prepareSQLiteDSN(dsn string) error {
	path, ok := sqliteFilePath(dsn)
	if !ok {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Size() != legacyStubSize {
		return nil
	}

	header, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if string(header) != sqliteMagic {
		return nil
	}

	return os.Rename(path, path+".legacy-stub")
}

// sqliteFilePath extracts an on-disk path from a database/sql DSN. It returns
// false for in-memory databases, which must never be quarantined.
func sqliteFilePath(dsn string) (string, bool) {
	raw := strings.TrimSpace(dsn)
	if raw == "" || raw == ":memory:" {
		return "", false
	}
	raw = strings.TrimPrefix(raw, "file:")

	if idx := strings.IndexByte(raw, '?'); idx >= 0 {
		query := raw[idx+1:]
		raw = raw[:idx]
		if strings.Contains(query, "mode=memory") {
			return "", false
		}
	}

	if raw == "" || raw == ":memory:" {
		return "", false
	}
	return raw, true
}
