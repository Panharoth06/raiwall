package grpc

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/google/uuid"
	"google.golang.org/grpc"
)

const (
	// DefaultMaxBodySize is the maximum body payload buffered for WAF inspection (1 MB).
	DefaultMaxBodySize = 1024 * 1024
	// DefaultListenAddr is the default gRPC listening address.
	DefaultListenAddr = ":50051"
)

// ExtProcConfig configures the Envoy External Processor sidecar server.
type ExtProcConfig struct {
	ListenAddr  string
	MaxBodySize int
	WAFEngine   waf.WAFEnginePort
	RingBuffer  *telemetry.RingBuffer
}

// ExtProcServer implements ExternalProcessorServer.
type ExtProcServer struct {
	cfg        ExtProcConfig
	grpcServer *grpc.Server
	listener   net.Listener
	mu         sync.Mutex
	running    bool
}

// NewServer initializes a new ExtProcServer.
func NewServer(cfg ExtProcConfig) *ExtProcServer {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultListenAddr
	}
	if cfg.MaxBodySize <= 0 {
		cfg.MaxBodySize = DefaultMaxBodySize
	}
	if cfg.WAFEngine == nil {
		cfg.WAFEngine = waf.NewSemanticEngine()
	}

	return &ExtProcServer{
		cfg: cfg,
	}
}

// ServeListener serves gRPC traffic on the provided net.Listener.
func (s *ExtProcServer) ServeListener(lis net.Listener) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.listener = lis
	s.grpcServer = grpc.NewServer()
	RegisterExternalProcessorServer(s.grpcServer, s)
	s.running = true
	s.mu.Unlock()

	return s.grpcServer.Serve(lis)
}

// Start binds to the configured listen address and starts the gRPC server in the background.
func (s *ExtProcServer) Start() error {
	lis, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("sidecar listen failed on %s: %w", s.cfg.ListenAddr, err)
	}
	go func() {
		_ = s.ServeListener(lis)
	}()
	return nil
}

// Stop gracefully stops the gRPC server.
func (s *ExtProcServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	s.running = false
}

func sendImmediateResponse(stream ExternalProcessor_ProcessServer, statusCode int, body, details string) error {
	var httpStatus StatusCode
	switch statusCode {
	case 429:
		httpStatus = StatusCode_TooManyRequests
	case 503:
		httpStatus = StatusCode_ServiceUnavailable
	default:
		httpStatus = StatusCode_Forbidden
	}

	return stream.Send(&ProcessingResponse{
		Response: &ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &ImmediateResponse{
				Status:  &HttpStatus{Code: httpStatus},
				Body:    body,
				Details: details,
			},
		},
	})
}

func extractClientIP(headers http.Header) net.IP {
	if xff := headers.Get("x-forwarded-for"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := net.ParseIP(strings.TrimSpace(parts[0]))
			if ip != nil {
				return ip
			}
		}
	}
	if xrip := headers.Get("x-real-ip"); xrip != "" {
		ip := net.ParseIP(strings.TrimSpace(xrip))
		if ip != nil {
			return ip
		}
	}
	return net.ParseIP("127.0.0.1")
}

func (s *ExtProcServer) recordTelemetry(host, path, method string, ip net.IP, ruleID, action string, status int) {
	if s.cfg.RingBuffer == nil {
		return
	}
	ipStr := "127.0.0.1"
	if ip != nil {
		ipStr = ip.String()
	}
	s.cfg.RingBuffer.Push(&telemetry.ForensicEvent{
		EventID:    "sp-" + uuid.New().String()[:8],
		Timestamp:  time.Now().UTC(),
		Host:       host,
		Path:       path,
		Method:     method,
		ClientIP:   ipStr,
		RuleID:     ruleID,
		Action:     action,
		StatusCode: status,
	})
}
