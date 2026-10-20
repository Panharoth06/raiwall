package telemetry

import "context"

// ForensicStorePort defines the driven port for forensic log storage and querying.
type ForensicStorePort = ForensicStore

// AlertNotifierPort defines the driven port for outbound notifications.
type AlertNotifierPort interface {
	Send(ctx context.Context, title string, message string, fields map[string]string) error
}

// TelemetryRecorderPort defines the driving port for recording forensic events.
type TelemetryRecorderPort interface {
	Record(event *ForensicEvent)
	Flush() error
}
