package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/Panharoth06/raiwall/pkg/control/db"
	"github.com/stretchr/testify/require"
)

func setupTestMCP(t *testing.T) (*Server, *db.Store) {
	dsn := fmt.Sprintf("file:test_mcp_%d.db", time.Now().UnixNano())
	store, err := db.InitDB(dsn)
	require.NoError(t, err)

	server := NewServer(store)
	return server, store
}

func TestMCP_InitializeAndListTools(t *testing.T) {
	server, store := setupTestMCP(t)
	defer store.Close()

	ctx := context.Background()

	// 1. Initialize Handshake
	initReq := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}
	resp := server.HandleRequest(ctx, initReq)
	require.Nil(t, resp.Error)
	resMap, ok := resp.Result.(map[string]any)
	require.True(t, ok)
	require.Equal(t, "2024-11-05", resMap["protocolVersion"])

	// 2. List Tools
	listReq := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}
	resp = server.HandleRequest(ctx, listReq)
	require.Nil(t, resp.Error)
	toolsRes, ok := resp.Result.(map[string]any)
	require.True(t, ok)
	toolsList, ok := toolsRes["tools"].([]ToolDefinition)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(toolsList), 5)
}

func TestMCP_ToolExecution(t *testing.T) {
	server, store := setupTestMCP(t)
	defer store.Close()

	ctx := context.Background()

	// 1. get_waf_status
	statusParams, _ := json.Marshal(map[string]any{
		"name":      "get_waf_status",
		"arguments": map[string]any{},
	})
	resp := server.HandleRequest(ctx, &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params:  statusParams,
	})
	require.Nil(t, resp.Error)
	callRes := resp.Result.(*ToolCallResult)
	require.False(t, callRes.IsError)
	require.Contains(t, callRes.Content[0].Text, "healthy")

	// 2. create_exception_rule
	excParams, _ := json.Marshal(map[string]any{
		"name": "create_exception_rule",
		"arguments": map[string]any{
			"param_name":  "q",
			"rule_id":     "SEMANTIC_SQLI",
			"description": "Created via AI agent",
		},
	})
	resp = server.HandleRequest(ctx, &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params:  excParams,
	})
	require.Nil(t, resp.Error)
	callRes = resp.Result.(*ToolCallResult)
	require.False(t, callRes.IsError)
	require.Contains(t, callRes.Content[0].Text, "Successfully created exception rule")

	// 3. apply_configuration
	applyParams, _ := json.Marshal(map[string]any{
		"name": "apply_configuration",
		"arguments": map[string]any{
			"author":      "Claude Desktop",
			"description": "Applied test rule",
		},
	})
	resp = server.HandleRequest(ctx, &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "tools/call",
		Params:  applyParams,
	})
	require.Nil(t, resp.Error)
	callRes = resp.Result.(*ToolCallResult)
	require.False(t, callRes.IsError)
	require.Contains(t, callRes.Content[0].Text, "swapped to version 1")

	// 4. rollback_configuration
	rbParams, _ := json.Marshal(map[string]any{
		"name": "rollback_configuration",
		"arguments": map[string]any{
			"version": 1,
		},
	})
	resp = server.HandleRequest(ctx, &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      6,
		Method:  "tools/call",
		Params:  rbParams,
	})
	require.Nil(t, resp.Error)
	callRes = resp.Result.(*ToolCallResult)
	require.False(t, callRes.IsError)
	require.Contains(t, callRes.Content[0].Text, "Successfully rolled back")
}

func TestMCP_StdioLoop(t *testing.T) {
	server, store := setupTestMCP(t)
	defer store.Close()

	ctx := context.Background()

	input := `{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"

	var inBuf bytes.Buffer
	inBuf.WriteString(input)

	var outBuf bytes.Buffer
	err := server.ServeStdio(ctx, &inBuf, &outBuf)
	require.NoError(t, err)

	lines := bytes.Split(bytes.TrimSpace(outBuf.Bytes()), []byte("\n"))
	require.Len(t, lines, 2)

	var resp1, resp2 JSONRPCResponse
	require.NoError(t, json.Unmarshal(lines[0], &resp1))
	require.NoError(t, json.Unmarshal(lines[1], &resp2))

	require.Equal(t, float64(1), resp1.ID)
	require.Equal(t, float64(2), resp2.ID)
}

func init() {
	// Initialize default snapshot for tests
	config.StoreSnapshot(config.NewConfigSnapshot(1, config.ModeDefense, nil))
}
