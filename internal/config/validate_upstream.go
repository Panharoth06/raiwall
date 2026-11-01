package config

import (
	"fmt"
	"strings"
)

// Health-check status codes must be a real HTTP status.
const (
	minHealthCheckStatus = 100
	maxHealthCheckStatus = 599
)

// validateUpstreams checks backend targets shared by applications and
// forwarding rules.
func (v *validator) validateUpstreams(prefix string, upstreams []Upstream) {
	for j, up := range upstreams {
		at := fmt.Sprintf("%s.upstreams[%d]", prefix, j)
		if !validDial(up.Dial) {
			v.add("%s.dial %q is not a valid host:port", at, up.Dial)
		}
		if up.Weight < 0 || up.MaxFails < 0 {
			v.add("%s weights and max_fails must be non-negative", at)
		}
		if up.FailTimeout < 0 {
			v.add("%s.fail_timeout must be non-negative", at)
		}
		if up.HealthCheckInterval < 0 {
			v.add("%s.health_check_interval must be non-negative", at)
		}
		if up.HealthCheckPath != "" && !strings.HasPrefix(up.HealthCheckPath, "/") {
			v.add("%s.health_check_path %q must start with /", at, up.HealthCheckPath)
		}
		if up.HealthCheckStatus != 0 &&
			(up.HealthCheckStatus < minHealthCheckStatus || up.HealthCheckStatus > maxHealthCheckStatus) {
			v.add("%s.health_check_status %d must be between %d and %d",
				at, up.HealthCheckStatus, minHealthCheckStatus, maxHealthCheckStatus)
		}
	}
}
