package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/Panharoth06/raiwall/pkg/acl"
	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/Panharoth06/raiwall/pkg/control/db"
	"github.com/Panharoth06/raiwall/pkg/engine"
	"github.com/Panharoth06/raiwall/pkg/sidecar"
	"github.com/Panharoth06/raiwall/pkg/telemetry"
)

func init() {
	fs := flag.NewFlagSet("sidecar", flag.ExitOnError)
	fs.String("listen", ":50051", "Listen address for Envoy ext_proc gRPC service")
	fs.String("db", "file:raiwall_control.db", "Path or DSN to SQLite database")
	fs.String("redis", "", "Redis address for cluster synchronization (optional)")
	fs.Int("max-body-size", 1048576, "Maximum body size in bytes to buffer for inspection (default 1MB)")

	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "sidecar",
		Usage: "[--listen <addr>] [--db <dsn>] [--redis <addr>] [--max-body-size <bytes>]",
		Short: "Runs the standalone Envoy ext_proc v3 gRPC sidecar service",
		Flags: fs,
		Func:  cmdSidecar,
	})
}

func cmdSidecar(flags caddycmd.Flags) (int, error) {
	listenAddr := flags.String("listen")
	if listenAddr == "" {
		listenAddr = ":50051"
	}
	dbDSN := flags.String("db")
	if dbDSN == "" {
		dbDSN = "file:raiwall_control.db"
	}
	maxBodySize := flags.Int("max-body-size")
	if maxBodySize <= 0 {
		maxBodySize = 1048576
	}

	// Initialize ring buffer and semantic engine
	ringBuffer := telemetry.NewRingBuffer(telemetry.RingBufferConfig{
		Capacity:      1000,
		FlushInterval: 500 * time.Millisecond,
		Handler:       func(events []*telemetry.ForensicEvent) error { return nil },
	})
	defer ringBuffer.Close()

	wafEngine := engine.NewSemanticEngine()

	// Initialize database and compiler if available
	store, err := db.InitDB(dbDSN)
	if err == nil {
		defer store.Close()
		snap, err := config.CompileSnapshot(context.Background(), store)
		if err == nil && snap != nil && len(snap.Exceptions) > 0 {
			if ee, err := acl.NewExceptionEngine(snap.Exceptions...); err == nil {
				wafEngine.SetExceptionEngine(ee)
			}
		}
	}

	server := sidecar.NewServer(sidecar.ExtProcConfig{
		ListenAddr:  listenAddr,
		MaxBodySize: maxBodySize,
		WAFEngine:   wafEngine,
		RingBuffer:  ringBuffer,
	})

	if err := server.Start(); err != nil {
		return 1, err
	}
	defer server.Stop()

	fmt.Printf("Envoy ext_proc gRPC sidecar running on %s\n", listenAddr)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	return 0, nil
}
