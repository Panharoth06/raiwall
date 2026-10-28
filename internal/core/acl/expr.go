package acl

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// ACLRule represents an access control policy evaluated via compiled bytecode.
type ACLRule struct {
	Name               string `json:"name"`
	Expression         string `json:"expression"`
	Action             Action `json:"action"` // allow, block, challenge, redirect, audit
	Priority           int    `json:"priority"`
	StatusCode         int    `json:"status_code,omitempty"`
	RedirectURL        string `json:"redirect_url,omitempty"`
	ContinueInspection bool   `json:"continue_inspection,omitempty"`

	compiled        *vm.Program
	tableProvider   func() *BARTTable
	ipGroupProvider func() *IPGroupManager
}

// CompileWithProvider compiles the rule expression into bytecode using expr with a dynamic BARTTable provider.
func (r *ACLRule) CompileWithProvider(provider func() *BARTTable) error {
	return r.CompileWithProviders(provider, nil)
}

// CompileWithProviders compiles the rule expression with dynamic BARTTable and IPGroupManager providers.
func (r *ACLRule) CompileWithProviders(provider func() *BARTTable, ipGroupProvider func() *IPGroupManager) error {
	r.tableProvider = provider
	r.ipGroupProvider = ipGroupProvider
	if strings.TrimSpace(r.Expression) == "" {
		return fmt.Errorf("empty expression for ACL rule %q", r.Name)
	}

	options := []expr.Option{
		expr.Env(&EvalEnv{}),
		expr.AsBool(),
		expr.Function("in_cidr", evalInCIDR, func(string, string) bool { return false }),
		expr.Function("regex_match", evalRegexMatch, func(string, string) bool { return false }),
		expr.Function("has_prefix", evalHasPrefix, func(string, string) bool { return false }),
		expr.Function("str_contains", evalContains, func(string, string) bool { return false }),
		expr.Function("in_feed", func(params ...any) (any, error) {
			if len(params) != 2 {
				return false, fmt.Errorf("in_feed requires 2 arguments (ip, feedName)")
			}
			ipStr, ok1 := params[0].(string)
			feed, ok2 := params[1].(string)
			if !ok1 || !ok2 {
				return false, nil
			}
			var bt *BARTTable
			if provider != nil {
				bt = provider()
			}
			if bt == nil {
				return false, nil
			}
			ip := CleanIP(ipStr)
			if ip == nil {
				return false, nil
			}
			return bt.InFeed(ip, feed), nil
		}, func(string, string) bool { return false }),
		expr.Function("ip_group", func(params ...any) (any, error) {
			if len(params) != 1 {
				return IPGroupRef{}, fmt.Errorf("ip_group requires 1 argument (groupName)")
			}
			name, ok := params[0].(string)
			if !ok {
				return IPGroupRef{}, fmt.Errorf("ip_group argument must be a string")
			}
			var mgr *IPGroupManager
			if ipGroupProvider != nil {
				mgr = ipGroupProvider()
			}
			return IPGroupRef{Name: name, manager: mgr}, nil
		}, func(string) IPGroupRef { return IPGroupRef{} }),
		expr.Function("in_ip_group_op", func(params ...any) (any, error) {
			if len(params) != 2 {
				return false, fmt.Errorf("in operator requires 2 arguments")
			}
			ipStr, ok1 := params[0].(string)
			ref, ok2 := params[1].(IPGroupRef)
			if !ok1 || !ok2 {
				return false, nil
			}
			if ref.manager != nil {
				return ref.manager.InGroupStr(ipStr, ref.Name), nil
			}
			var bt *BARTTable
			if provider != nil {
				bt = provider()
			}
			if bt != nil {
				ip := CleanIP(ipStr)
				if ip != nil {
					return bt.InFeed(ip, ref.Name), nil
				}
			}
			return false, nil
		}, func(string, IPGroupRef) bool { return false }),
		expr.Operator("in", "in_ip_group_op"),
		expr.Function("in_ip_group", func(params ...any) (any, error) {
			if len(params) != 2 {
				return false, fmt.Errorf("in_ip_group requires 2 arguments (ip, groupName)")
			}
			ipStr, ok1 := params[0].(string)
			group, ok2 := params[1].(string)
			if !ok1 || !ok2 {
				return false, nil
			}
			if ipGroupProvider != nil {
				if mgr := ipGroupProvider(); mgr != nil {
					return mgr.InGroupStr(ipStr, group), nil
				}
			}
			var bt *BARTTable
			if provider != nil {
				bt = provider()
			}
			if bt != nil {
				ip := CleanIP(ipStr)
				if ip != nil {
					return bt.InFeed(ip, group), nil
				}
			}
			return false, nil
		}, func(string, string) bool { return false }),
	}

	prog, err := expr.Compile(r.Expression, options...)
	if err != nil {
		return fmt.Errorf("compile ACL rule %q (%q): %w", r.Name, r.Expression, err)
	}

	r.compiled = prog

	// Default status codes
	if r.Action == ActionBlock && r.StatusCode == 0 {
		r.StatusCode = http.StatusForbidden
	}
	if r.Action == ActionRedirect && r.StatusCode == 0 {
		r.StatusCode = http.StatusFound
	}

	return nil
}

// CompileWithAll compiles the rule expression with explicit BARTTable and IPGroupManager.
func (r *ACLRule) CompileWithAll(bartTable *BARTTable, ipGroupMgr *IPGroupManager) error {
	return r.CompileWithProviders(func() *BARTTable { return bartTable }, func() *IPGroupManager { return ipGroupMgr })
}

// Compile compiles the rule expression into bytecode using expr.
func (r *ACLRule) Compile(bartTable *BARTTable) error {
	return r.CompileWithProviders(func() *BARTTable { return bartTable }, nil)
}

// Eval evaluates the compiled rule directly against an EvalEnv.
func (r *ACLRule) Eval(env *EvalEnv) (bool, error) {
	if r.compiled == nil {
		if err := r.Compile(nil); err != nil {
			return false, err
		}
	}
	out, err := vm.Run(r.compiled, env)
	if err != nil {
		return false, err
	}
	matched, ok := out.(bool)
	if !ok {
		return false, fmt.Errorf("rule %q did not evaluate to boolean", r.Name)
	}
	return matched, nil
}

// evalContains is a helper for expr str_contains.
func evalContains(params ...any) (any, error) {
	if len(params) != 2 {
		return false, fmt.Errorf("contains requires 2 arguments (str, substr)")
	}
	s, ok1 := params[0].(string)
	sub, ok2 := params[1].(string)
	if !ok1 || !ok2 {
		return false, nil
	}
	return strings.Contains(s, sub), nil
}
