package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Panharoth06/raiwall/pkg/control/db"
)

// JSONRPCRequest represents a standard JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents a standard JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id,omitempty"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError defines structured JSON-RPC errors.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Server handles MCP protocol requests over SSE and Stdio.
type Server struct {
	store    *db.Store
	registry *Registry
}

// NewServer creates a new MCP protocol server instance.
func NewServer(store *db.Store) *Server {
	return &Server{
		store:    store,
		registry: NewRegistry(store),
	}
}

// Registry returns the underlying tool registry.
func (s *Server) Registry() *Registry {
	return s.registry
}

// HandleRequest processes a JSON-RPC 2.0 request and returns the JSON-RPC response.
func (s *Server) HandleRequest(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	if req.JSONRPC != "2.0" {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &JSONRPCError{Code: -32600, Message: "invalid Request: jsonrpc must be '2.0'"},
		}
	}

	switch req.Method {
	case "initialize":
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"serverInfo": map[string]any{
					"name":    "raiwall-mcp",
					"version": "1.0.0",
				},
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
			},
		}

	case "notifications/initialized":
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{},
		}

	case "tools/list":
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": s.registry.ListTools(),
			},
		}

	case "tools/call":
		var callParams struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &callParams); err != nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: -32602, Message: "invalid params: " + err.Error()},
			}
		}

		res, err := s.registry.Execute(ctx, callParams.Name, callParams.Arguments)
		if err != nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: -32603, Message: "tool execution failed: " + err.Error()},
			}
		}

		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  res,
		}

	default:
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &JSONRPCError{Code: -32601, Message: fmt.Sprintf("method not found: %q", req.Method)},
		}
	}
}

// ServeSSE handles the Server-Sent Events MCP endpoint at /.raiwall/api/mcp.
func (s *Server) ServeSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Advertise message endpoint
		_, _ = fmt.Fprintf(w, "event: endpoint\ndata: /.raiwall/api/mcp/message\n\n")
		flusher.Flush()

		// Keep connection alive until client disconnects
		<-r.Context().Done()
		return
	}

	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// ServeMessage handles incoming JSON-RPC POST requests to /.raiwall/api/mcp/message.
func (s *Server) ServeMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(JSONRPCResponse{
			JSONRPC: "2.0",
			Error:   &JSONRPCError{Code: -32700, Message: "parse error: " + err.Error()},
		})
		return
	}

	resp := s.HandleRequest(r.Context(), &req)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ServeStdio runs the JSON-RPC message loop over standard input/output.
func (s *Server) ServeStdio(ctx context.Context, r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			errResp := JSONRPCResponse{
				JSONRPC: "2.0",
				Error:   &JSONRPCError{Code: -32700, Message: "parse error: " + err.Error()},
			}
			out, _ := json.Marshal(errResp)
			_, _ = fmt.Fprintln(w, string(out))
			continue
		}

		resp := s.HandleRequest(ctx, &req)
		out, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(w, string(out))
	}
	return scanner.Err()
}
