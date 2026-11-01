package caddy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

func probeStatusBackend(status int) roundTripperFunc {
	return func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	}
}

func TestUpstreamProbeHonorsExpectedStatus(t *testing.T) {
	for _, tc := range []struct {
		name     string
		expected int
		returned int
		healthy  bool
	}{
		{"custom 204 healthy", 204, 204, true},
		{"custom 204 rejects 200", 204, 200, false},
		{"default 200 healthy", 0, 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := NewUpstreamPool([]control.UpstreamTarget{{
				Dial: "backend.internal:8080", MaxFails: 1, HealthCheckStatus: tc.expected,
				HealthCheckInterval: time.Hour,
			}})
			b := pool.Backends()[0]
			b.client.Transport = probeStatusBackend(tc.returned)
			b.probe(context.Background())
			if b.IsHealthy() != tc.healthy {
				t.Fatalf("healthy=%v, want %v", b.IsHealthy(), tc.healthy)
			}
		})
	}
}

func TestUpstreamTargetStatusRoundTripAndKey(t *testing.T) {
	in := control.UpstreamTarget{Dial: "a:1", HealthCheckStatus: 204}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out control.UpstreamTarget
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.HealthCheckStatus != 204 {
		t.Fatalf("round trip lost status: %+v", out)
	}
	if TargetsKey([]control.UpstreamTarget{in}) == TargetsKey([]control.UpstreamTarget{{Dial: "a:1"}}) {
		t.Fatal("pool key must change when the expected status changes")
	}
}
