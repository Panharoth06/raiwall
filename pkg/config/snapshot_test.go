package config

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestParseRunMode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    RunMode
		wantErr bool
	}{
		{name: "defense lowercase", input: "defense", want: ModeDefense, wantErr: false},
		{name: "defense uppercase", input: "DEFENSE", want: ModeDefense, wantErr: false},
		{name: "defense whitespace", input: "  defense  ", want: ModeDefense, wantErr: false},
		{name: "audit lowercase", input: "audit", want: ModeAudit, wantErr: false},
		{name: "offline lowercase", input: "offline", want: ModeOffline, wantErr: false},
		{name: "invalid mode", input: "invalid_mode", want: "", wantErr: true},
		{name: "empty string", input: "", want: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRunMode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRunMode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseRunMode(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestConfigSnapshotLookup(t *testing.T) {
	app1 := &AppConfig{
		ID:        "app-1",
		Name:      "App One",
		Hostnames: []string{"example.com", "api.example.com"},
		Mode:      ModeDefense,
	}
	app2 := &AppConfig{
		ID:        "app-2",
		Name:      "App Two",
		Hostnames: []string{"admin.internal"},
		Mode:      ModeOffline,
	}

	snap := NewConfigSnapshot(1, ModeDefense, []*AppConfig{app1, app2})

	tests := []struct {
		name      string
		host      string
		wantFound bool
		wantID    string
	}{
		{name: "exact host", host: "example.com", wantFound: true, wantID: "app-1"},
		{name: "host with port", host: "example.com:8443", wantFound: true, wantID: "app-1"},
		{name: "subdomain host", host: "api.example.com", wantFound: true, wantID: "app-1"},
		{name: "case-insensitive host", host: "Admin.Internal:443", wantFound: true, wantID: "app-2"},
		{name: "unmatched host", host: "unknown.org", wantFound: false, wantID: ""},
		{name: "empty host", host: "", wantFound: false, wantID: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, found := snap.GetAppForHost(tt.host)
			if found != tt.wantFound {
				t.Fatalf("GetAppForHost(%q) found = %v, want %v", tt.host, found, tt.wantFound)
			}
			if found && app.ID != tt.wantID {
				t.Errorf("GetAppForHost(%q) app.ID = %q, want %q", tt.host, app.ID, tt.wantID)
			}
		})
	}
}

func TestSnapshotManagerConcurrentAccess(t *testing.T) {
	initialSnap := NewConfigSnapshot(1, ModeDefense, []*AppConfig{
		{
			ID:        "initial",
			Hostnames: []string{"test.local"},
			Mode:      ModeDefense,
		},
	})

	sm := NewSnapshotManager(initialSnap)
	loaded := sm.LoadSnapshot()
	if loaded == nil || loaded.Version != 1 {
		t.Fatalf("expected version 1, got %v", loaded)
	}

	// Concurrent race test: multiple goroutines reading and writing snapshots simultaneously
	var wg sync.WaitGroup
	const (
		numReaders = 20
		numWriters = 5
		iterations = 1000
	)

	stopCh := make(chan struct{})

	// Readers
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					s := sm.LoadSnapshot()
					if s == nil {
						t.Errorf("reader %d observed nil snapshot", readerID)
						return
					}
					// Verify lookups are consistent and safe
					_, _ = s.GetAppForHost("test.local")
				}
			}
		}(i)
	}

	// Writers
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				newSnap := NewConfigSnapshot(uint64(writerID*iterations+j), ModeAudit, []*AppConfig{
					{
						ID:        fmt.Sprintf("app-w%d-%d", writerID, j),
						Hostnames: []string{fmt.Sprintf("host-%d.local", j)},
						Mode:      ModeAudit,
					},
				})
				sm.StoreSnapshot(newSnap)
				time.Sleep(10 * time.Microsecond)
			}
		}(i)
	}

	// Wait for writers to finish
	time.Sleep(100 * time.Millisecond)
	close(stopCh)
	wg.Wait()

	// Verify global functions work
	StoreSnapshot(initialSnap)
	gSnap := LoadSnapshot()
	if gSnap == nil || gSnap.Version != 1 {
		t.Fatalf("expected global snapshot version 1, got %v", gSnap)
	}
}
