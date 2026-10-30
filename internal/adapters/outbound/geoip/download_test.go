package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// tarFixture builds a GeoLite2-shaped gzipped tarball containing one mmdb file.
func tarFixture(t *testing.T, member string, content []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	if err := tw.WriteHeader(&tar.Header{
		Name:     "GeoLite2-Test_20260101/" + member,
		Mode:     0o644,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

func withDownloadServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	original := downloadEndpoint
	downloadEndpoint = srv.URL
	t.Cleanup(func() { downloadEndpoint = original })
	return srv
}

func TestEnsureDatabases_DownloadsMissingFile(t *testing.T) {
	var edition string
	withDownloadServer(t, func(w http.ResponseWriter, r *http.Request) {
		edition = r.URL.Query().Get("edition_id")
		if key := r.URL.Query().Get("license_key"); key != "test-key" {
			http.Error(w, "bad key", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(tarFixture(t, "GeoLite2-Country.mmdb", []byte("country-db")))
	})

	path := filepath.Join(t.TempDir(), "nested", "GeoLite2-Country.mmdb")
	refreshed, err := EnsureDatabases(context.Background(), "test-key",
		Database{Edition: "GeoLite2-Country", Path: path})
	if err != nil {
		t.Fatalf("EnsureDatabases: %v", err)
	}
	if edition != "GeoLite2-Country" {
		t.Errorf("expected edition GeoLite2-Country, got %q", edition)
	}
	if len(refreshed) != 1 || refreshed[0] != "GeoLite2-Country" {
		t.Errorf("expected one refreshed edition, got %v", refreshed)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(data) != "country-db" {
		t.Errorf("unexpected contents %q", data)
	}
}

func TestEnsureDatabases_SkipsFreshFile(t *testing.T) {
	withDownloadServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("fresh database should not be downloaded again")
	})

	path := filepath.Join(t.TempDir(), "GeoLite2-City.mmdb")
	if err := os.WriteFile(path, []byte("fresh"), 0o640); err != nil {
		t.Fatalf("seed database: %v", err)
	}

	refreshed, err := EnsureDatabases(context.Background(), "test-key",
		Database{Edition: "GeoLite2-City", Path: path})
	if err != nil {
		t.Fatalf("EnsureDatabases: %v", err)
	}
	if len(refreshed) != 0 {
		t.Errorf("expected no refresh, got %v", refreshed)
	}
}

func TestEnsureDatabases_RefreshesStaleFile(t *testing.T) {
	withDownloadServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tarFixture(t, "GeoLite2-City.mmdb", []byte("updated")))
	})

	path := filepath.Join(t.TempDir(), "GeoLite2-City.mmdb")
	if err := os.WriteFile(path, []byte("stale"), 0o640); err != nil {
		t.Fatalf("seed database: %v", err)
	}
	stale := time.Now().Add(-DatabaseRefreshAge - 24*time.Hour)
	if err := os.Chtimes(path, stale, stale); err != nil {
		t.Fatalf("age database: %v", err)
	}

	refreshed, err := EnsureDatabases(context.Background(), "test-key",
		Database{Edition: "GeoLite2-City", Path: path})
	if err != nil {
		t.Fatalf("EnsureDatabases: %v", err)
	}
	if len(refreshed) != 1 {
		t.Errorf("expected one refreshed edition, got %v", refreshed)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "updated" {
		t.Errorf("expected refreshed contents, got %q", data)
	}
}

func TestEnsureDatabases_RequiresLicenseKey(t *testing.T) {
	_, err := EnsureDatabases(context.Background(), "  ", Database{Edition: "GeoLite2-Country", Path: "/tmp/x.mmdb"})
	if !errors.Is(err, ErrLicenseKeyMissing) {
		t.Fatalf("expected ErrLicenseKeyMissing, got %v", err)
	}
}

func TestEnsureDatabases_ReportsHTTPFailure(t *testing.T) {
	withDownloadServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid license key", http.StatusUnauthorized)
	})

	_, err := EnsureDatabases(context.Background(), "test-key",
		Database{Edition: "GeoLite2-ASN", Path: filepath.Join(t.TempDir(), "asn.mmdb")})
	if err == nil {
		t.Fatal("expected an error for a rejected download")
	}
}

func TestEnsureDatabases_RejectsArchiveWithoutMMDB(t *testing.T) {
	withDownloadServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tarFixture(t, "README.txt", []byte("no database here")))
	})

	_, err := EnsureDatabases(context.Background(), "test-key",
		Database{Edition: "GeoLite2-Country", Path: filepath.Join(t.TempDir(), "country.mmdb")})
	if err == nil {
		t.Fatal("expected an error for an archive without a database")
	}
}
