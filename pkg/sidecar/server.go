package sidecar

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/Panharoth06/raiwall/pkg/engine"
	"github.com/Panharoth06/raiwall/pkg/telemetry"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	DefaultMaxBodySize = 1024 * 1024 // 1 MB
	DefaultListenAddr  = ":50051"
)

// ExtProcConfig configures the Envoy External Processor sidecar server.
type ExtProcConfig struct {
	ListenAddr  string
	MaxBodySize int
	WAFEngine   engine.WAFEngine
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
		cfg.WAFEngine = engine.NewSemanticEngine()
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

// Process handles bidirectional gRPC streaming inspection requests from Envoy.
func (s *ExtProcServer) Process(stream ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()

	var (
		clientIP     net.IP
		method       string
		path         string
		host         string
		headers      = make(http.Header)
		bodyBuf      = make([]byte, 0)
		bodyTooLarge = false
	)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if status.Code(err) == codes.Canceled {
				return nil
			}
			return err
		}

		// 1. Process Request Headers
		if hReq := req.GetRequestHeaders(); hReq != nil {
			if hReq.Headers != nil {
				for _, h := range hReq.Headers.Headers {
					val := h.Value
					if val == "" && len(h.RawValue) > 0 {
						val = string(h.RawValue)
					}
					k := strings.ToLower(h.Key)
					headers.Add(k, val)

					switch k {
					case ":method":
						method = val
					case ":path":
						path = val
					case ":authority", "host":
						if host == "" {
							host = val
						}
					}
				}
			}

			// Extract client IP
			clientIP = extractClientIP(headers)

			// Snapshot evaluation
			snap := config.GetActiveSnapshot()
			if snap != nil {
				if app, ok := snap.GetAppForHost(host); ok && app.Mode == config.ModeOffline {
					return sendImmediateResponse(stream, 503, "Service Offline for Maintenance", "raiwall_mode_offline")
				}

				// Evaluate ACL rules
				for _, r := range snap.ACLRules {
					if r.Action == "block" && strings.Contains(strings.ToLower(path), "/admin") && !isInternalIP(clientIP) {
						s.recordTelemetry(host, path, method, clientIP, r.Name, "block", 403)
						return sendImmediateResponse(stream, 403, "Access Denied by Raiwall ACL Policy", "raiwall_acl_block")
					}
				}
			}

			// Allow headers to proceed
			resp := &ProcessingResponse{
				Response: &ProcessingResponse_RequestHeaders{
					RequestHeaders: &HeadersResponse{},
				},
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
			continue
		}

		// 2. Process Request Body
		if bReq := req.GetRequestBody(); bReq != nil {
			chunk := bReq.Body
			if !bodyTooLarge {
				if len(bodyBuf)+len(chunk) > s.cfg.MaxBodySize {
					bodyTooLarge = true
					bodyBuf = nil // Free buffer to prevent OOM
				} else {
					bodyBuf = append(bodyBuf, chunk...)
				}
			}

			if bReq.EndOfStream {
				// If not too large and has body, inspect with semantic engine
				if !bodyTooLarge && len(bodyBuf) > 0 {
					reqCtx := &engine.RequestContext{
						ClientIP: clientIP,
						Method:   method,
						Host:     host,
						Path:     path,
						Headers:  headers,
						Body:     bodyBuf,
						Context:  ctx,
					}

					verdict, err := s.cfg.WAFEngine.InspectRequest(reqCtx)
					if err == nil && verdict != nil && verdict.Action == engine.ActionBlock {
						s.recordTelemetry(host, path, method, clientIP, verdict.RuleID, "block", 403)
						msg := fmt.Sprintf("<html><body><h1>403 Forbidden</h1><p>Blocked by Raiwall Semantic WAF [%s]</p></body></html>", verdict.RuleID)
						return sendImmediateResponse(stream, 403, msg, "raiwall_semantic_waf_block")
					}
				}

				// Safe request body
				s.recordTelemetry(host, path, method, clientIP, "", "allow", 200)
				resp := &ProcessingResponse{
					Response: &ProcessingResponse_RequestBody{
						RequestBody: &BodyResponse{},
					},
				}
				if err := stream.Send(resp); err != nil {
					return err
				}
				continue
			}

			// Intermediate body chunk: acknowledge and continue buffering
			resp := &ProcessingResponse{
				Response: &ProcessingResponse_RequestBody{
					RequestBody: &BodyResponse{},
				},
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
			continue
		}

		// Default passthrough for response headers or body
		if req.GetResponseHeaders() != nil {
			resp := &ProcessingResponse{
				Response: &ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &HeadersResponse{},
				},
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		} else if req.GetResponseBody() != nil {
			resp := &ProcessingResponse{
				Response: &ProcessingResponse_ResponseBody{
					ResponseBody: &BodyResponse{},
				},
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		}
	}
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

func isInternalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
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
