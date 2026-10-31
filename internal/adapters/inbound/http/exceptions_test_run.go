package api

import (
	"encoding/json"
	"net/http"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/waf/crs"
)

// ExceptionTestRequest encapsulates a dry-run test request for exception evaluation.
type ExceptionTestRequest struct {
	Rule          ExceptionDTO           `json:"rule"`
	SampleRequest ExceptionSampleRequest `json:"sample_request"`
	Request       *struct {
		Host      string            `json:"host"`
		Path      string            `json:"path"`
		Method    string            `json:"method"`
		Location  string            `json:"location"`
		ParamName string            `json:"param_name"`
		Params    map[string]string `json:"params"`
		RuleID    string            `json:"rule_id"`
	} `json:"request,omitempty"`
}

// ExceptionSampleRequest specifies sample HTTP attributes to match against.
type ExceptionSampleRequest struct {
	Host      string `json:"host"`
	Path      string `json:"path"`
	Method    string `json:"method"`
	Location  string `json:"location"`
	ParamName string `json:"param_name"`
	RuleID    string `json:"rule_id"`
}

// ExceptionEffect describes how a matching exception affects one detection
// engine. Directive is set when the effect is a concrete Coraza ctl action.
type ExceptionEffect struct {
	Engine    string `json:"engine"`
	Directive string `json:"directive,omitempty"`
	Detail    string `json:"detail"`
}

// ExceptionTestResponse represents the outcome of the simulation.
type ExceptionTestResponse struct {
	Matched bool              `json:"matched"`
	Reason  string            `json:"reason"`
	Effects []ExceptionEffect `json:"effects,omitempty"`
}

func (s *Server) handleTestException(w http.ResponseWriter, r *http.Request) {
	var req ExceptionTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.Rule.PathPrefix == "" && req.Rule.PathRegex == "" && req.Rule.Path != "" {
		req.Rule.PathPrefix = req.Rule.Path
	}
	if req.Rule.Description == "" && req.Rule.Reason != "" {
		req.Rule.Description = req.Rule.Reason
	}
	if req.Rule.Method == "ALL" {
		req.Rule.Method = "*"
	}
	if req.Rule.RuleID == "ALL" {
		req.Rule.RuleID = "*"
	}

	if req.Request != nil {
		if req.SampleRequest.Host == "" {
			req.SampleRequest.Host = req.Request.Host
		}
		if req.SampleRequest.Path == "" {
			req.SampleRequest.Path = req.Request.Path
		}
		if req.SampleRequest.Method == "" {
			req.SampleRequest.Method = req.Request.Method
		}
		if req.SampleRequest.Location == "" {
			req.SampleRequest.Location = req.Request.Location
			if req.SampleRequest.Location == "" {
				req.SampleRequest.Location = "query"
			}
		}
		if req.SampleRequest.RuleID == "" {
			req.SampleRequest.RuleID = req.Request.RuleID
		}
		if req.SampleRequest.ParamName == "" {
			if req.Request.ParamName != "" {
				req.SampleRequest.ParamName = req.Request.ParamName
			} else {
				for k := range req.Request.Params {
					req.SampleRequest.ParamName = k
					break
				}
			}
		}
	}

	rule := acl.ExceptionRule{
		ID:          "test-rule",
		Description: req.Rule.Description,
		Host:        req.Rule.Host,
		PathRegex:   req.Rule.PathRegex,
		PathPrefix:  req.Rule.PathPrefix,
		Method:      req.Rule.Method,
		Location:    req.Rule.Location,
		ParamName:   req.Rule.ParamName,
		ParamRegex:  req.Rule.ParamRegex,
		RuleID:      req.Rule.RuleID,
	}

	if err := rule.Compile(); err != nil {
		respondJSON(w, http.StatusOK, ExceptionTestResponse{
			Matched: false,
			Reason:  "regex compilation failed: " + err.Error(),
		})
		return
	}

	matched := rule.Matches(
		req.SampleRequest.Host,
		req.SampleRequest.Path,
		req.SampleRequest.Method,
		req.SampleRequest.Location,
		req.SampleRequest.ParamName,
		req.SampleRequest.RuleID,
	)

	reason := "rule matched criteria successfully"
	if !matched {
		reason = "request criteria did not match rule parameters"
	}

	var effects []ExceptionEffect
	if matched {
		effects = append(effects, ExceptionEffect{
			Engine: "semantic",
			Detail: "suppresses matching semantic detections for the scoped request",
		})
		effects = append(effects, crsEffect(rule))
	}

	respondJSON(w, http.StatusOK, ExceptionTestResponse{
		Matched: matched,
		Reason:  reason,
		Effects: effects,
	})
}

// crsEffect reports whether the exception translates into a Coraza ctl action.
func crsEffect(rule acl.ExceptionRule) ExceptionEffect {
	if rule.ParamRegex != "" {
		return ExceptionEffect{
			Engine: "crs",
			Detail: "parameter-regex targets are semantic-only; CRS rules are not removed",
		}
	}
	suppression, ok := crs.SuppressionFor(rule.RuleID, rule.Location, rule.ParamName)
	if !ok {
		return ExceptionEffect{
			Engine: "crs",
			Detail: "no CRS rule matches this rule_id (semantic-only)",
		}
	}
	return ExceptionEffect{
		Engine:    "crs",
		Directive: suppression.Directive(),
		Detail:    "removes the CRS rule for matching requests",
	}
}
