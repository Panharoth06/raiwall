package telemetry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// EventFilter defines matching criteria for SSE subscribers.
type EventFilter struct {
	Action      string `json:"action"`
	RuleID      string `json:"rule_id"`
	Country     string `json:"country"`
	MinSeverity string `json:"min_severity"`
}

// Matches returns true if the event satisfies all non-empty filter constraints.
func (f EventFilter) Matches(event *ForensicEvent) bool {
	if event == nil {
		return false
	}
	if f.Action != "" && !strings.EqualFold(event.Action, f.Action) {
		return false
	}
	if f.RuleID != "" && !strings.EqualFold(event.RuleID, f.RuleID) {
		return false
	}
	if f.Country != "" && !strings.EqualFold(event.GeoData.Country, f.Country) {
		return false
	}
	if f.MinSeverity != "" {
		minRank := severityRank(f.MinSeverity)
		evRank := severityRank(event.Severity)
		if evRank < minRank {
			return false
		}
	}
	return true
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0 // info / unknown
	}
}

// Subscriber represents an active SSE client connection.
type Subscriber struct {
	id     uint64
	filter EventFilter
	ch     chan *ForensicEvent
}

// Channel returns the receive-only channel for events dispatched to this subscriber.
func (s *Subscriber) Channel() <-chan *ForensicEvent {
	return s.ch
}

// EventStreamer manages live Server-Sent Events fan-out to connected browser dashboards.
type EventStreamer struct {
	mu          sync.RWMutex
	subscribers map[uint64]*Subscriber
	nextID      atomic.Uint64
}

// NewEventStreamer creates a new SSE EventStreamer.
func NewEventStreamer() *EventStreamer {
	return &EventStreamer{
		subscribers: make(map[uint64]*Subscriber),
	}
}

// Subscribe adds a new client subscriber with the given filter, returning the channel and an unsubscribe func.
func (s *EventStreamer) Subscribe(filter EventFilter) (*Subscriber, func()) {
	id := s.nextID.Add(1)
	sub := &Subscriber{
		id:     id,
		filter: filter,
		ch:     make(chan *ForensicEvent, 128),
	}

	s.mu.Lock()
	s.subscribers[id] = sub
	s.mu.Unlock()

	unsubscribe := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.subscribers[id]; ok {
			delete(s.subscribers, id)
			close(sub.ch)
		}
	}

	return sub, unsubscribe
}

// SubscriberCount returns the current count of active SSE client subscribers.
func (s *EventStreamer) SubscriberCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.subscribers)
}

// Broadcast distributes a sanitized ForensicEvent to all matching subscribers non-blockingly.
func (s *EventStreamer) Broadcast(event *ForensicEvent) {
	if event == nil {
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, sub := range s.subscribers {
		if sub.filter.Matches(event) {
			select {
			case sub.ch <- event:
			default:
				// Buffer full for slow subscriber: drop to avoid slowing other clients
			}
		}
	}
}

// ServeHTTP handles incoming HTTP SSE connections (`GET /.raiwall/api/events/stream`).
func (s *EventStreamer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	q := r.URL.Query()
	filter := EventFilter{
		Action:      q.Get("action"),
		RuleID:      q.Get("rule_id"),
		Country:     q.Get("country"),
		MinSeverity: q.Get("min_severity"),
	}

	sub, unsubscribe := s.Subscribe(filter)
	defer unsubscribe()

	// Initial comment to confirm connection
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	heartbeatTicker := time.NewTicker(15 * time.Second)
	defer heartbeatTicker.Stop()

	notify := r.Context().Done()

	for {
		select {
		case <-notify:
			return

		case <-heartbeatTicker.C:
			_, err := fmt.Fprint(w, ": ping\n\n")
			if err != nil {
				return
			}
			flusher.Flush()

		case event, ok := <-sub.ch:
			if !ok {
				return
			}
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}

			_, err = fmt.Fprintf(w, "data: %s\n\n", data)
			if err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
