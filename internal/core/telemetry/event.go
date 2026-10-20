package telemetry

import (
	"encoding/json"
	"time"
)

// GeoData holds geographic and network intelligence for a client IP.
type GeoData struct {
	Country   string  `json:"country,omitempty"`
	Continent string  `json:"continent,omitempty"`
	City      string  `json:"city,omitempty"`
	ASN       uint    `json:"asn,omitempty"`
	ASOrg     string  `json:"as_org,omitempty"`
	Latitude  float64 `json:"latitude,omitempty"`
	Longitude float64 `json:"longitude,omitempty"`
}

// ForensicEvent captures detailed request metadata for forensic analysis and real-time observability.
type ForensicEvent struct {
	EventID          string              `json:"event_id"`
	Timestamp        time.Time           `json:"timestamp"`
	Host             string              `json:"host"`
	Path             string              `json:"path"`
	Method           string              `json:"method"`
	ClientIP         string              `json:"client_ip"`
	JA4              string              `json:"ja4,omitempty"`
	GeoData          GeoData             `json:"geo_data,omitempty"`
	RuleID           string              `json:"rule_id,omitempty"`
	Action           string              `json:"action"`   // allow, block, challenge, ban
	Severity         string              `json:"severity"` // info, low, medium, high, critical
	Headers          map[string]string   `json:"headers,omitempty"`
	TruncatedPayload string              `json:"truncated_payload,omitempty"`
	Latency          time.Duration       `json:"latency"`
	StatusCode       int                 `json:"status_code"`
	PayloadLocation  string              `json:"payload_location,omitempty"` // URLPATH, QUERY, HEADER, BODY, COOKIE
	MatchedToken     string              `json:"matched_token,omitempty"`
	AttackCategory   string              `json:"attack_category,omitempty"`
	ResponseHeaders  map[string][]string `json:"response_headers,omitempty"`
	ResponseBody     []byte              `json:"response_body,omitempty"`
}

// ToJSON serializes the ForensicEvent to JSON bytes.
func (e *ForensicEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// ForensicEventFromJSON parses JSON bytes into a ForensicEvent.
func ForensicEventFromJSON(data []byte) (*ForensicEvent, error) {
	var event ForensicEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, err
	}
	return &event, nil
}

// Clone creates a deep copy of the ForensicEvent.
func (e *ForensicEvent) Clone() *ForensicEvent {
	if e == nil {
		return nil
	}
	cpy := *e
	if e.Headers != nil {
		cpy.Headers = make(map[string]string, len(e.Headers))
		for k, v := range e.Headers {
			cpy.Headers[k] = v
		}
	}
	if e.ResponseHeaders != nil {
		cpy.ResponseHeaders = make(map[string][]string, len(e.ResponseHeaders))
		for k, vals := range e.ResponseHeaders {
			valsCopy := make([]string, len(vals))
			copy(valsCopy, vals)
			cpy.ResponseHeaders[k] = valsCopy
		}
	}
	if len(e.ResponseBody) > 0 {
		cpy.ResponseBody = make([]byte, len(e.ResponseBody))
		copy(cpy.ResponseBody, e.ResponseBody)
	}
	return &cpy
}

// LatencyMs returns the latency in floating-point milliseconds.
func (e *ForensicEvent) LatencyMs() float64 {
	return float64(e.Latency.Microseconds()) / 1000.0
}
