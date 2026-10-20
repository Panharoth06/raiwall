package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/mcp"
	"github.com/Panharoth06/raiwall/internal/core/control"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	snap := control.GetActiveSnapshot()
	var ver uint64
	var mode control.RunMode = control.ModeDefense
	if snap != nil {
		ver = snap.Version
		mode = snap.DefaultMode
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"status":         "healthy",
		"active_version": ver,
		"mode":           mode,
		"timestamp":      time.Now().UTC(),
	})
}

func (s *Server) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	snap := control.GetActiveSnapshot()
	var ver uint64 = 1
	if snap != nil {
		ver = snap.Version
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"mode":            "standalone",
		"redis_connected": false,
		"active_version":  ver,
		"channel":         "raiwall:cluster",
	})
}

func (s *Server) handleMCPMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		respondError(w, http.StatusBadRequest, "failed to read request body: "+err.Error())
		return
	}

	var req mcp.JSONRPCRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(mcp.JSONRPCResponse{
			JSONRPC: "2.0",
			Error:   &mcp.JSONRPCError{Code: -32700, Message: "parse error: " + err.Error()},
		})
		return
	}

	// Role-based authorization for MCP tools
	if authCtx, ok := AuthFromContext(r.Context()); ok && authCtx.Role == "viewer" {
		if req.Method == "tools/call" {
			var callParams struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(req.Params, &callParams)
			// Disallow mutating tools for viewer
			if callParams.Name == "create_exception_rule" || callParams.Name == "apply_configuration" || callParams.Name == "rollback_configuration" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(mcp.JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Error:   &mcp.JSONRPCError{Code: -32603, Message: fmt.Sprintf("role viewer is not authorized to execute mutating tool %q", callParams.Name)},
				})
				return
			}
		}
	}

	resp := s.mcpServer.HandleRequest(r.Context(), &req)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
