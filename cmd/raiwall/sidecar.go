package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/grpc"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage"
	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
)

func init() {
	fs := flag.NewFlagSet("sidecar", flag.ExitOnError)
	fs.String("listen", ":50051", "Listen address for Envoy ext_proc gRPC service")
	fs.String("db", "file:raiwall_control.db", "Path or DSN to SQLite database")
	fs.String("dsn", "", "Database connection DSN (overrides --db)")
	fs.String("driver", "", "Database driver (sqlite, postgres; auto-detected if empty)")
	fs.String("redis", "", "Redis address for cluster synchronization (optional)")
	fs.Int("max-body-size", 1048576, "Maximum body size in bytes to buffer for inspection (default 1MB)")

	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "sidecar",
		Usage: "[--listen <addr>] [--db <dsn>] [--dsn <dsn>] [--driver <driver>] [--redis <addr>] [--max-body-size <bytes>]",
		Short: "Runs the standalone Envoy ext_proc v3 gRPC sidecar service",
		Flags: fs,
		Func:  cmdSidecar,
	})
}

func cmdSidecar(flags caddycmd.Flags) (int, error) {
	listenAddr := getFlagString(flags, "listen", ":50051")
	dbDSN := getFlagString(flags, "dsn", "")
	if dbDSN == "" {
		dbDSN = getFlagString(flags, "db", "file:raiwall_control.db")
	}
	driver := getFlagString(flags, "driver", "")
	maxBodySize := getFlagInt(flags, "max-body-size", 1048576)

	// Initialize ring buffer and semantic engine
	ringBuffer := telemetry.NewRingBuffer(telemetry.RingBufferConfig{
		Capacity:      1000,
		FlushInterval: 500 * time.Millisecond,
		Handler:       func(events []*telemetry.ForensicEvent) error { return nil },
	})
	defer ringBuffer.Close()

	wafEngine := waf.NewSemanticEngine()

	// Initialize database and compiler if available
	ctx := context.Background()
	store, err := storage.OpenControlStore(ctx, driver, dbDSN)
	if err == nil {
		defer store.Close()
		snap, err := control.CompileSnapshot(ctx, store)
		if err == nil && snap != nil && len(snap.Exceptions) > 0 {
			if ee, err := acl.NewExceptionEngine(snap.Exceptions...); err == nil {
				wafEngine.SetExceptionEngine(ee)
			}
		}
	}

	server := grpc.NewServer(grpc.ExtProcConfig{
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
