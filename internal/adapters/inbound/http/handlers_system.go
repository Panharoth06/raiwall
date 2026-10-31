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

// defaultClusterChannel matches the redis adapter's default; standalone mode
// still reports the channel peers would use.
const defaultClusterChannel = "raiwall:cluster:events"

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
		"auto_apply":     s.autoApply,
		"timestamp":      time.Now().UTC(),
	})
}

type updateAutoApplyRequest struct {
	AutoApply bool `json:"auto_apply"`
}

func (s *Server) handleUpdateAutoApply(w http.ResponseWriter, r *http.Request) {
	var req updateAutoApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	s.SetAutoApply(req.AutoApply)
	respondJSON(w, http.StatusOK, map[string]any{
		"success":    true,
		"auto_apply": s.AutoApplyEnabled(),
	})
}

func (s *Server) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	if s.clusterStatus != nil {
		respondJSON(w, http.StatusOK, s.clusterStatus.ClusterStatus(r.Context()))
		return
	}

	snap := control.GetActiveSnapshot()
	var ver uint64 = 1
	if snap != nil {
		ver = snap.Version
	}
	banCount := 0
	if s.banManager != nil {
		banCount = s.banManager.Count()
	}

	respondJSON(w, http.StatusOK, ClusterStatus{
		Mode:           "standalone",
		RedisConnected: false,
		ActiveVersion:  ver,
		AppliedVersion: ver,
		Channel:        defaultClusterChannel,
		BanCount:       banCount,
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
