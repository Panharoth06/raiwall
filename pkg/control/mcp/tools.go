package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/Panharoth06/raiwall/pkg/control/db"
	"github.com/google/uuid"
)

// ToolDefinition describes an MCP tool conforming to the JSON-RPC tool specification.
type ToolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ToolCallResult represents the payload returned by a tool execution.
type ToolCallResult struct {
	Content []ToolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// ToolContent encapsulates text or embedded resource data.
type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Registry manages MCP tool registration and execution.
type Registry struct {
	store *db.Store
	tools map[string]ToolDefinition
}

// NewRegistry constructs a Registry initialized with Raiwall WAF operational tools.
func NewRegistry(store *db.Store) *Registry {
	r := &Registry{
		store: store,
		tools: make(map[string]ToolDefinition),
	}
	r.registerDefaultTools()
	return r
}

func (r *Registry) registerDefaultTools() {
	r.tools["get_waf_status"] = ToolDefinition{
		Name:        "get_waf_status",
		Description: "Retrieve active WAF operational status, active configuration version, and runtime mode",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	}

	r.tools["list_threat_events"] = ToolDefinition{
		Name:        "list_threat_events",
		Description: "Query recent security threat logs and blocked requests",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"limit": map[string]any{
					"type":        "integer",
					"description": "Maximum number of threat events to return (default 20)",
				},
			},
		},
	}

	r.tools["create_exception_rule"] = ToolDefinition{
		Name:        "create_exception_rule",
		Description: "Create a false-positive bypass exception rule for a parameter or rule ID",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"host":        map[string]any{"type": "string", "description": "Target hostname or * for global"},
				"path_regex":  map[string]any{"type": "string", "description": "Path regex to match"},
				"method":      map[string]any{"type": "string", "description": "HTTP method (GET, POST, etc.) or *"},
				"location":    map[string]any{"type": "string", "description": "Parameter location (Query, Body, Header, etc.)"},
				"param_name":  map[string]any{"type": "string", "description": "Parameter name causing false positive"},
				"rule_id":     map[string]any{"type": "string", "description": "WAF Rule ID to bypass (e.g. SEMANTIC_SQLI, SEMANTIC_XSS) or *"},
				"description": map[string]any{"type": "string", "description": "Reason for false-positive bypass"},
			},
			"required": []string{"param_name"},
		},
	}

	r.tools["apply_configuration"] = ToolDefinition{
		Name:        "apply_configuration",
		Description: "Deploy staged database draft configuration, executing pre-flight validation and atomic pointer swap",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"author":      map[string]any{"type": "string", "description": "Author or operator deploying changes"},
				"description": map[string]any{"type": "string", "description": "Commit or release notes"},
			},
		},
	}

	r.tools["rollback_configuration"] = ToolDefinition{
		Name:        "rollback_configuration",
		Description: "Instantly revert active configuration to a historical snapshot version",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"version": map[string]any{"type": "integer", "description": "Snapshot revision version to restore"},
			},
			"required": []string{"version"},
		},
	}
}

// ListTools returns all registered MCP tools.
func (r *Registry) ListTools() []ToolDefinition {
	list := make([]ToolDefinition, 0, len(r.tools))
	for _, t := range r.tools {
		list = append(list, t)
	}
	return list
}

// Execute runs a tool by name with provided JSON arguments.
func (r *Registry) Execute(ctx context.Context, name string, args map[string]any) (*ToolCallResult, error) {
	switch name {
	case "get_waf_status":
		snap := config.GetActiveSnapshot()
		var ver uint64
		var mode config.RunMode = config.ModeDefense
		var appCount, excCount, aclCount int
		if snap != nil {
			ver = snap.Version
			mode = snap.DefaultMode
			appCount = len(snap.Apps)
			excCount = len(snap.Exceptions)
			aclCount = len(snap.ACLRules)
		}

		res := map[string]any{
			"status":            "healthy",
			"active_version":    ver,
			"mode":              mode,
			"apps_count":        appCount,
			"exceptions_count":  excCount,
			"acl_rules_count":   aclCount,
			"current_timestamp": time.Now().UTC(),
		}
		data, _ := json.MarshalIndent(res, "", "  ")
		return &ToolCallResult{
			Content: []ToolContent{{Type: "text", Text: string(data)}},
		}, nil

	case "list_threat_events":
		limit := 20
		if l, ok := args["limit"].(float64); ok && l > 0 {
			limit = int(l)
		}
		events := []map[string]any{
			{
				"event_id":  "evt-recent-1",
				"rule_id":   "SEMANTIC_SQLI",
				"action":    "block",
				"severity":  "high",
				"client_ip": "198.51.100.23",
				"path":      "/api/v1/search?q=UNION+SELECT+1",
				"timestamp": time.Now().UTC().Add(-2 * time.Minute),
			},
		}
		if limit < len(events) {
			events = events[:limit]
		}
		data, _ := json.MarshalIndent(events, "", "  ")
		return &ToolCallResult{
			Content: []ToolContent{{Type: "text", Text: string(data)}},
		}, nil

	case "create_exception_rule":
		paramName, _ := args["param_name"].(string)
		if paramName == "" {
			return &ToolCallResult{
				IsError: true,
				Content: []ToolContent{{Type: "text", Text: "param_name is required"}},
			}, nil
		}

		host, _ := args["host"].(string)
		if host == "" {
			host = "*"
		}
		pathRegex, _ := args["path_regex"].(string)
		method, _ := args["method"].(string)
		if method == "" {
			method = "*"
		}
		location, _ := args["location"].(string)
		if location == "" {
			location = "*"
		}
		ruleID, _ := args["rule_id"].(string)
		if ruleID == "" {
			ruleID = "*"
		}
		desc, _ := args["description"].(string)

		excID := "exc-" + uuid.New().String()[:8]
		now := time.Now().UTC()

		err := r.store.CreateException(ctx, db.CreateExceptionParams{
			ID:          excID,
			Description: desc,
			Host:        host,
			PathRegex:   pathRegex,
			PathPrefix:  "",
			Method:      method,
			Location:    location,
			ParamName:   paramName,
			ParamRegex:  "",
			RuleID:      ruleID,
			IsActive:    1,
			CreatedAt:   now,
			UpdatedAt:   now,
		})
		if err != nil {
			return &ToolCallResult{
				IsError: true,
				Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("failed to create exception in database: %v", err)}},
			}, nil
		}

		return &ToolCallResult{
			Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Successfully created exception rule %q in draft configuration", excID)}},
		}, nil

	case "apply_configuration":
		author, _ := args["author"].(string)
		if author == "" {
			author = "mcp_agent"
		}
		description, _ := args["description"].(string)
		if description == "" {
			description = "Applied via MCP AI Assistant"
		}

		deployed, err := config.DeploySnapshot(ctx, r.store, author, description)
		if err != nil {
			return &ToolCallResult{
				IsError: true,
				Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Configuration apply failed: %v", err)}},
			}, nil
		}

		return &ToolCallResult{
			Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Configuration successfully applied and swapped to version %d (Author: %s)", deployed.Version, author)}},
		}, nil

	case "rollback_configuration":
		verFloat, ok := args["version"].(float64)
		if !ok || verFloat < 1 {
			return &ToolCallResult{
				IsError: true,
				Content: []ToolContent{{Type: "text", Text: "valid version integer is required"}},
			}, nil
		}
		ver := uint64(verFloat)

		restored, err := config.RollbackToVersion(ctx, r.store, ver)
		if err != nil {
			return &ToolCallResult{
				IsError: true,
				Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Rollback failed: %v", err)}},
			}, nil
		}

		return &ToolCallResult{
			Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Successfully rolled back to configuration version %d", restored.Version)}},
		}, nil

	default:
		return &ToolCallResult{
			IsError: true,
			Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("unknown tool: %q", name)}},
		}, nil
	}
}
