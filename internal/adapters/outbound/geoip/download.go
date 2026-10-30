package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// downloadEndpoint is the MaxMind GeoLite2 download API. It is a variable so
// tests can point it at a local fixture server.
var downloadEndpoint = "https://download.maxmind.com/app/geoip_download"

// DatabaseRefreshAge is how old a database file may be before a refresh is
// attempted. MaxMind publishes GeoLite2 updates twice a week.
const DatabaseRefreshAge = 30 * 24 * time.Hour

// ErrLicenseKeyMissing is returned when a refresh is requested without a
// MaxMind license key.
var ErrLicenseKeyMissing = errors.New("geoip: maxmind license key is not configured")

// Database describes a MaxMind edition and where it should be stored.
type Database struct {
	Edition string
	Path    string
}

// EnsureDatabases downloads every database that is missing or older than
// DatabaseRefreshAge, writing each atomically next to its final path. It returns
// the editions that were refreshed. Failures are collected so one unreachable
// edition does not block the others.
func EnsureDatabases(ctx context.Context, licenseKey string, databases ...Database) ([]string, error) {
	if strings.TrimSpace(licenseKey) == "" {
		return nil, ErrLicenseKeyMissing
	}

	var (
		refreshed []string
		errs      []error
	)
	for _, db := range databases {
		if strings.TrimSpace(db.Path) == "" || strings.TrimSpace(db.Edition) == "" {
			continue
		}
		if !needsRefresh(db.Path, DatabaseRefreshAge) {
			continue
		}
		if err := downloadDatabase(ctx, licenseKey, db); err != nil {
			errs = append(errs, fmt.Errorf("download %s: %w", db.Edition, err))
			continue
		}
		refreshed = append(refreshed, db.Edition)
	}

	return refreshed, errors.Join(errs...)
}

// needsRefresh reports whether path is missing, empty, or older than maxAge.
func needsRefresh(path string, maxAge time.Duration) bool {
	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	return info.Size() == 0 || time.Since(info.ModTime()) > maxAge
}

func downloadDatabase(ctx context.Context, licenseKey string, db Database) error {
	url := fmt.Sprintf("%s?edition_id=%s&license_key=%s&suffix=tar.gz",
		downloadEndpoint, db.Edition, licenseKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	mmdb, err := extractMMDB(resp.Body)
	if err != nil {
		return err
	}
	return writeAtomic(db.Path, mmdb)
}

// extractMMDB reads a gzipped tarball and returns the first .mmdb member.
func extractMMDB(r io.Reader) ([]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("archive does not contain an .mmdb database")
		}
		if err != nil {
			return nil, fmt.Errorf("read tar entry: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || !strings.HasSuffix(hdr.Name, ".mmdb") {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", hdr.Name, err)
		}
		return data, nil
	}
}

// writeAtomic writes data to path via a temporary file in the same directory so
// a concurrent reader never observes a partially written database.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".geoip-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := io.Copy(tmp, bytes.NewReader(data)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Chmod(tmpName, 0o640); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename to %s: %w", path, err)
	}
	return nil
}
