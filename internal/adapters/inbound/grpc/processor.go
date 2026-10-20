package grpc

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RequestProcessor encapsulates sidecar request inspection logic.
type RequestProcessor struct {
	engine      waf.WAFEnginePort
	maxBodySize int
}

// NewRequestProcessor creates a new RequestProcessor.
func NewRequestProcessor(wafEngine waf.WAFEnginePort, maxBodySize int) *RequestProcessor {
	if maxBodySize <= 0 {
		maxBodySize = DefaultMaxBodySize
	}
	if wafEngine == nil {
		wafEngine = waf.NewSemanticEngine()
	}
	return &RequestProcessor{
		engine:      wafEngine,
		maxBodySize: maxBodySize,
	}
}

// Inspect inspects the assembled request. If body exceeds maxBodySize, inspection of body is skipped.
func (p *RequestProcessor) Inspect(ctx context.Context, clientIP net.IP, method, host, path string, headers http.Header, body []byte) (*waf.Verdict, error) {
	reqCtx := &waf.RequestContext{
		ClientIP: clientIP,
		Method:   method,
		Host:     host,
		Path:     path,
		Headers:  headers,
		Body:     body,
		Context:  ctx,
	}

	return p.engine.InspectRequest(reqCtx)
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

			clientIP = extractClientIP(headers)
			if blocked, err := s.evalSnapshotACL(stream, host, path, method, clientIP, headers); blocked || err != nil {
				return err
			}

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
					bodyBuf = nil
				} else {
					bodyBuf = append(bodyBuf, chunk...)
				}
			}

			if bReq.EndOfStream {
				if !bodyTooLarge && len(bodyBuf) > 0 {
					if blocked, err := s.inspectWAF(ctx, stream, host, path, method, clientIP, headers, bodyBuf); blocked || err != nil {
						return err
					}
				}

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

		// Passthrough for responses
		if req.GetResponseHeaders() != nil {
			if err := stream.Send(&ProcessingResponse{
				Response: &ProcessingResponse_ResponseHeaders{ResponseHeaders: &HeadersResponse{}},
			}); err != nil {
				return err
			}
		} else if req.GetResponseBody() != nil {
			if err := stream.Send(&ProcessingResponse{
				Response: &ProcessingResponse_ResponseBody{ResponseBody: &BodyResponse{}},
			}); err != nil {
				return err
			}
		}
	}
}

func (s *ExtProcServer) evalSnapshotACL(stream ExternalProcessor_ProcessServer, host, path, method string, clientIP net.IP, headers http.Header) (bool, error) {
	snap := control.GetActiveSnapshot()
	if snap == nil {
		return false, nil
	}
	if app, ok := snap.GetAppForHost(host); ok && app.Mode == control.ModeOffline {
		return true, sendImmediateResponse(stream, 503, "Service Offline for Maintenance", "raiwall_mode_offline")
	}

	env := buildEvalEnv(clientIP, method, path, host, headers)
	for _, r := range snap.ACLRules {
		matched, err := r.Eval(env)
		if err != nil {
			continue
		}
		if matched {
			if r.Action == acl.ActionBlock {
				sc := r.StatusCode
				if sc == 0 {
					sc = 403
				}
				s.recordTelemetry(host, path, method, clientIP, r.Name, "block", sc)
				return true, sendImmediateResponse(stream, sc, "Access Denied by Raiwall ACL Policy", "raiwall_acl_block")
			} else if r.Action == acl.ActionAllow {
				break
			}
		}
	}
	return false, nil
}

func (s *ExtProcServer) inspectWAF(ctx context.Context, stream ExternalProcessor_ProcessServer, host, path, method string, clientIP net.IP, headers http.Header, body []byte) (bool, error) {
	snap := control.GetActiveSnapshot()
	if semEng, ok := s.cfg.WAFEngine.(*waf.SemanticEngine); ok {
		if snap != nil && len(snap.Exceptions) > 0 {
			excEng, _ := acl.NewExceptionEngine(snap.Exceptions...)
			semEng.SetExceptionEngine(excEng)
		} else {
			semEng.SetExceptionEngine(nil)
		}
	}

	reqCtx := &waf.RequestContext{
		ClientIP: clientIP,
		Method:   method,
		Host:     host,
		Path:     path,
		Headers:  headers,
		Body:     body,
		Context:  ctx,
	}

	verdict, err := s.cfg.WAFEngine.InspectRequest(reqCtx)
	if err == nil && verdict != nil && verdict.Action == waf.ActionBlock {
		s.recordTelemetry(host, path, method, clientIP, verdict.RuleID, "block", 403)
		msg := fmt.Sprintf("<html><body><h1>403 Forbidden</h1><p>Blocked by Raiwall Semantic WAF [%s]</p></body></html>", verdict.RuleID)
		return true, sendImmediateResponse(stream, 403, msg, "raiwall_semantic_waf_block")
	}
	return false, nil
}

func buildEvalEnv(clientIP net.IP, method, path, host string, headers http.Header) *acl.EvalEnv {
	headerMap := make(map[string]string)
	for k, v := range headers {
		if len(v) > 0 {
			headerMap[strings.ToLower(k)] = v[0]
		}
	}
	env := &acl.EvalEnv{
		IP:        clientIP.String(),
		ClientIP:  clientIP.String(),
		Method:    method,
		Path:      path,
		Host:      host,
		Headers:   headerMap,
		Cookies:   make(map[string]string),
		Query:     make(map[string]string),
		UserAgent: headers.Get("user-agent"),
	}
	if cookieHdr := headers.Get("cookie"); cookieHdr != "" {
		for _, p := range strings.Split(cookieHdr, ";") {
			p = strings.TrimSpace(p)
			if k, v, found := strings.Cut(p, "="); found {
				env.Cookies[k] = v
			}
		}
	}
	if idx := strings.IndexByte(path, '?'); idx != -1 && idx+1 < len(path) {
		for _, pair := range strings.Split(path[idx+1:], "&") {
			if k, v, found := strings.Cut(pair, "="); found {
				env.Query[k] = v
			}
		}
	}
	return env
}
