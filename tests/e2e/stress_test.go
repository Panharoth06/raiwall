//go:build integration

package e2e

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/caddy"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeSnapshotWithResponseToggle(version uint64, enabled bool) *control.ConfigSnapshot {
	snap := control.NewConfigSnapshot(version, control.ModeDefense, nil)
	snap.WAFPolicy = &control.WAFPolicySnapshot{
		DetectionMode: string(control.ModeDefense),
		Sensitivity:   "medium",
		Response: &control.ResponsePolicySnapshot{
			Enabled:        &enabled,
			Mode:           "audit",
			InspectHeaders: &enabled,
			InspectBody:    &enabled,
			BodyLimit:      1024 * 1024,
			HardCap:        8 * 1024 * 1024,
			Decompress:     &enabled,
			ContentTypes:   control.DefaultContentTypes(),
			DLP: &control.DLPPolicySnapshot{
				Enabled:           &enabled,
				Action:            "audit",
				DetectPAN:         &enabled,
				DetectSecrets:     &enabled,
				DetectJWT:         &enabled,
				DetectPrivateKeys: &enabled,
				Redaction:         "[REDACTED]",
				MaxScanBytes:      1024 * 1024,
			},
		},
	}
	return snap
}

type stressResult struct {
	totalReqs      int
	falsePositives int
	p50            time.Duration
	p90            time.Duration
	p99            time.Duration
	startSys       uint64
	endSys         uint64
	startAlloc     uint64
	endAlloc       uint64
}

func runStressPhase(
	t *testing.T,
	mw *caddy.Middleware,
	next *e2eNextHandler,
	phaseName string,
	targetRPS int,
	duration time.Duration,
) stressResult {
	t.Helper()
	t.Logf("Starting stress phase '%s' at %d RPS for %v...", phaseName, targetRPS, duration)

	// Force GC and capture baseline memory
	runtime.GC()
	var mStart runtime.MemStats
	runtime.ReadMemStats(&mStart)

	interval := time.Second / time.Duration(targetRPS)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	stopTimer := time.NewTimer(duration)
	defer stopTimer.Stop()

	var latencies []time.Duration
	var falsePositives int
	var mu sync.Mutex
	var wg sync.WaitGroup

	reqCount := 0

	for {
		select {
		case <-stopTimer.C:
			goto Finished
		case <-ticker.C:
			reqCount++
			wg.Add(1)
			go func() {
				defer wg.Done()
				start := time.Now()
				req := httptest.NewRequest(http.MethodGet, "/benign", nil)
				req.RemoteAddr = "192.0.2.10:45678"
				rec := httptest.NewRecorder()
				err := mw.ServeHTTP(rec, req, next)
				elapsed := time.Since(start)

				mu.Lock()
				latencies = append(latencies, elapsed)
				if err != nil || rec.Code != http.StatusOK {
					falsePositives++
				}
				mu.Unlock()
			}()
		}
	}

Finished:
	wg.Wait()

	// Capture end memory
	runtime.GC()
	var mEnd runtime.MemStats
	runtime.ReadMemStats(&mEnd)

	require.NotEmpty(t, latencies, "Phase '%s' must have executed requests", phaseName)

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	n := len(latencies)
	p50 := latencies[int(float64(n)*0.50)]
	p90 := latencies[int(float64(n)*0.90)]
	p99 := latencies[int(float64(n)*0.99)]

	t.Logf("Phase '%s' completed: %d reqs, false_positives=%d, p50=%v, p90=%v, p99=%v, alloc_delta=%+d KB, sys_delta=%+d KB",
		phaseName, n, falsePositives, p50, p90, p99,
		int64(mEnd.Alloc-mStart.Alloc)/1024,
		int64(mEnd.Sys-mStart.Sys)/1024,
	)

	return stressResult{
		totalReqs:      n,
		falsePositives: falsePositives,
		p50:            p50,
		p90:            p90,
		p99:            p99,
		startSys:       mStart.Sys,
		endSys:         mEnd.Sys,
		startAlloc:     mStart.Alloc,
		endAlloc:       mEnd.Alloc,
	}
}

func TestStress_BenignOnOff(t *testing.T) {
	mw, _, next := setupDLPFixture(t)

	// Determine duration: defaults to 10s for normal integration tests.
	// When running FULL stress gate (e.g. via `make stress`), duration is 300s (5 min).
	stressDuration := 10 * time.Second
	if val := os.Getenv("STRESS_DURATION"); val != "" {
		if d, err := time.ParseDuration(val); err == nil && d > 0 {
			stressDuration = d
		}
	}

	const targetRPS = 500

	// 1. Phase 1: Response Inspection OFF (Baseline)
	control.StoreSnapshot(makeSnapshotWithResponseToggle(301, false))
	time.Sleep(100 * time.Millisecond) // Let snapshot propagate
	resOff := runStressPhase(t, mw, next, "Response-Inspection-OFF", targetRPS, stressDuration)

	// 2. Phase 2: Response Inspection ON (Active DLP + Outbound Inspection)
	control.StoreSnapshot(makeSnapshotWithResponseToggle(302, true))
	time.Sleep(100 * time.Millisecond) // Let snapshot propagate
	resOn := runStressPhase(t, mw, next, "Response-Inspection-ON", targetRPS, stressDuration)

	// 3. Gate Verification: Zero false positives
	assert.Equal(t, 0, resOff.falsePositives, "Phase OFF must have zero false positives on benign traffic")
	assert.Equal(t, 0, resOn.falsePositives, "Phase ON must have zero false positives on benign traffic")

	// 4. Gate Verification: p99 Latency Overhead <= 2 ms
	var p99Overhead time.Duration
	if resOn.p99 > resOff.p99 {
		p99Overhead = resOn.p99 - resOff.p99
	}
	t.Logf("Measured p99 Latency Overhead: %v (gate ceiling: 2ms; OFF p99=%v, ON p99=%v)", p99Overhead, resOff.p99, resOn.p99)

	// Under heavy CI load or race detector, allow small margin, but standard execution gates strictly at 2ms
	maxAllowedOverhead := 2 * time.Millisecond
	assert.LessOrEqual(t, p99Overhead, maxAllowedOverhead,
		fmt.Sprintf("Response inspection p99 latency overhead %v exceeded gate ceiling %v", p99Overhead, maxAllowedOverhead),
	)

	// 5. Gate Verification: RSS memory stability
	// Bounded memory growth: Alloc should not leak unbounded amounts of memory
	allocDeltaMB := float64(int64(resOn.endAlloc-resOn.startAlloc)) / (1024 * 1024)
	t.Logf("Phase ON Net Alloc Delta: %.2f MB", allocDeltaMB)
	assert.Less(t, allocDeltaMB, 50.0, "Allocated memory growth should remain stable under 50 MB")
}
