package waf

import "strings"

const javaDeserMagicHex = "aced0005"
const javaDeserMagicB64 = "ro0ab" // lowercase for matching against ToLower(v)

// Java serialization gadget / Fastjson / Jackson signatures.
var javaDeserMarkers = [...]string{
	"com.sun.rowset.jdbcrowsetimpl",
	"org.apache.commons.collections.functors",
	"org.springframework.aop.support.classfilters",
	"com.thoughtworks.xstream",
	"net.sf.cglib",
	"org.mozilla.javascript",
	"com.mchange.v2.c3p0",
	"org.apache.commons.beanutils",
	"com.rometools.rome",
	"jdk.jfr.internal",
}

// Fastjson / Jackson polymorphic @type gadget tokens.
var fastjsonGadgets = [...]string{
	"@type:", "\"@type\"",
	"jdbcrowsetimpl",
	"templatesimpl",
	"basicdatasource",
	"fileupload",
	"jarremotingexception",
}

// scanJavaDeser detects Java serialized object payload magic bytes and known
// gadget-chain class signatures used in deserialization RCE exploits.
func scanJavaDeser(v string) (Detection, bool) {
	lower := strings.ToLower(v)

	// Raw hex-serialized stream marker (aced 0005)
	if idx := strings.Index(lower, javaDeserMagicHex); idx != -1 {
		return Detection{
			Module:  ModuleJavaDeser,
			Level:   LevelStrong,
			Reason:  "Java serialized object magic bytes (aced0005)",
			Matched: snippet(v, idx, len(javaDeserMagicHex)),
		}, true
	}
	// Base64 image of the magic bytes (rO0AB) plus gadget class names carry no
	// distinctive charset, so Stage 2b must scan them on every benign value.
	if idx := strings.Index(lower, javaDeserMagicB64); idx != -1 {
		return Detection{
			Module:  ModuleJavaDeser,
			Level:   LevelStrong,
			Reason:  "Base64-encoded Java serialized object (rO0AB)",
			Matched: snippet(v, idx, len(javaDeserMagicB64)),
		}, true
	}

	// Known gadget-chain class signatures (Commons-Collections, C3P0, xstream, ...)
	for _, marker := range javaDeserMarkers {
		if idx := strings.Index(lower, marker); idx != -1 {
			return Detection{
				Module:  ModuleJavaDeser,
				Level:   LevelStrong,
				Reason:  "Java deserialization gadget signature",
				Matched: snippet(v, idx, len(marker)),
			}, true
		}
	}

	// Fastjson-style polymorphic typing gadgets
	for _, marker := range fastjsonGadgets {
		if idx := strings.Index(lower, marker); idx != -1 {
			return Detection{
				Module:  ModuleJavaDeser,
				Level:   LevelStrong,
				Reason:  "Fastjson @type deserialization gadget",
				Matched: snippet(v, idx, len(marker)),
			}, true
		}
	}

	return Detection{}, false
}

// Java expression-language injection payloads (OGNL / SpEL / Groovy).
var javaCodeInjStrong = [...]string{
	"#_memberaccess",       // OGNL sandbox bypass (Struts2 S2-061 etc.)
	"#context",             // OGNL context reference
	"t(java.lang.runtime)", // SpEL Runtime invocation
	"new java.lang.processbuilder",
	"runtime.getruntime().exec", // eval-style SpEL/EL
	"eval.me(",                  // Groovy Eval
	"groovy.lang.binding",
	"ognl.ognlruntime",
	"getclass().forname",
}

// scanJavaCodeInj detects OGNL, SpEL, and Groovy expression-language markers.
func scanJavaCodeInj(v string) (Detection, bool) {
	lower := strings.ToLower(v)

	for _, marker := range javaCodeInjStrong {
		if idx := strings.Index(lower, marker); idx != -1 {
			return Detection{
				Module:  ModuleJavaCodeInj,
				Level:   LevelStrong,
				Reason:  "Java expression language injection (OGNL/SpEL/Groovy)",
				Matched: snippet(v, idx, len(marker)),
			}, true
		}
	}

	// Weak: bare SpEL T(...) casts and OGNL trailing member access chained into parameters
	if (strings.Contains(v, "T(") && strings.Contains(lower, "runtime")) ||
		(strings.ContainsAny(v, "%") && strings.Contains(lower, "ognl")) ||
		(strings.Contains(lower, "jndi:") && strings.Contains(lower, "${")) {
		return Detection{
			Module:  ModuleJavaCodeInj,
			Level:   LevelWeak,
			Reason:  "Possible Java expression language injection",
			Matched: "spel/ognl heuristic",
		}, true
	}

	return Detection{}, false
}

// PHP dynamic execution markers.
var phpCodeStrong = [...]string{
	"eval(",   // any eval( in params is hostile unless base-64 decoding context
	"$_post[", // superglobal access
	"$_get[",
	"$_request[",
	"preg_replace('/", // /e modifier classic
	"preg_replace(\x22/",
	"create_function(",
	"assert(",
	"system(",
	"passthru(",
	"shell_exec(",
	"<?php",
	"<?=",
}

var phpBenignContexts = [...]string{
	"```", // markdown code fences echo PHP samples as prose
}

// scanPHPCodeInj detects PHP code injection attempts targeting eval()/assert()
// and classic preg_replace /e payloads.
func scanPHPCodeInj(v string) (Detection, bool) {
	lower := strings.ToLower(v)

	if !strings.ContainsAny(v, "(<") {
		return Detection{}, false
	}

	for _, marker := range phpCodeStrong {
		idx := strings.Index(lower, marker)
		if idx == -1 {
			continue
		}

		level := LevelStrong
		// Tolerate benign editorial contexts: code samples echoed as text
		// (e.g. markdown articles about PHP) that carry no superglobal access.
		hasSuperglobal := strings.Contains(lower, "$_")
		if !hasSuperglobal && containsAnyMarker(lower, phpBenignContexts[:]) {
			level = LevelWeak
		}

		return Detection{
			Module:  ModulePHPCodeInj,
			Level:   level,
			Reason:  "PHP code injection marker",
			Matched: snippet(v, idx, len(marker)),
		}, true
	}

	return Detection{}, false
}

// containsAnyMarker reports whether the haystack contains any of the markers.
func containsAnyMarker(haystack string, markers []string) bool {
	for _, m := range markers {
		if strings.Contains(haystack, m) {
			return true
		}
	}
	return false
}

// ASP code injection signatures.
var aspCodeStrong = [...]string{
	"<%@",            // @directive header (language / import)
	"<%response.",    // ASP Response object
	"<%set ",         // COM object instantiation
	"system.web.ui",  // ASP.NET namespace
	"viewstate[",     // Viewstate tampering
	"<script runat=", // ASP.NET server-side script
}

// scanASPCodeInj detects classic ASP <% %> tags and ASP.NET server markers.
func scanASPCodeInj(v string) (Detection, bool) {
	lower := strings.ToLower(v)

	if !strings.Contains(v, "<") {
		return Detection{}, false
	}

	for _, marker := range aspCodeStrong {
		idx := strings.Index(lower, marker)
		if idx != -1 {
			return Detection{
				Module:  ModuleASPCodeInj,
				Level:   LevelStrong,
				Reason:  "ASP code injection marker",
				Matched: snippet(v, idx, len(marker)),
			}, true
		}
	}

	// Classic ASP tag pair <% ... %>: strong only when it references executable constructs
	if idx := strings.Index(lower, "<%"); idx != -1 {
		endIdx := strings.Index(lower[idx:], "%>")
		if endIdx != -1 {
			interior := lower[idx : idx+endIdx]
			if strings.Contains(interior, "eval") || strings.Contains(interior, "execute") ||
				strings.Contains(interior, "request(") || strings.Contains(interior, "server.createobject") {
				return Detection{
					Module:  ModuleASPCodeInj,
					Level:   LevelStrong,
					Reason:  "Executable ASP server-side tag",
					Matched: snippet(v, idx, endIdx+2),
				}, true
			}
			return Detection{
				Module:  ModuleASPCodeInj,
				Level:   LevelWeak,
				Reason:  "ASP tag pair in parameter",
				Matched: "<%",
			}, true
		}
	}

	return Detection{}, false
}

// Template engine strong markers (Jinja2/Twig/Freemarker).
var sstiStrong = [...]string{
	"freemarker.template.utility.execute",
	"<#assign",
	"${\"freemarker",
	"class.classloader",
	"__globals__",
	"__subclasses__",
	"''.class.mro",
	"config.__class__.__init__",
	"request.application.__globals__",
}

// scanSSTI detects server-side template injection syntax across Jinja2, Twig,
// and Freemarker.
func scanSSTI(v string) (Detection, bool) {
	if !strings.ContainsAny(v, "{<") {
		return Detection{}, false
	}

	lower := strings.ToLower(v)

	for _, marker := range sstiStrong {
		idx := strings.Index(lower, marker)
		if idx != -1 {
			return Detection{
				Module:  ModuleSSTI,
				Level:   LevelStrong,
				Reason:  "Server-side template injection payload",
				Matched: snippet(v, idx, len(marker)),
			}, true
		}
	}

	// Mathematical expression probes: {{7*7}}, {{10*10}} — canonical SSTI canary
	if start := strings.Index(v, "{{"); start != -1 {
		if end := strings.Index(v[start:], "}}"); end != -1 {
			interior := v[start+2 : start+end]
			if containsArithmetic(interior) {
				return Detection{
					Module:  ModuleSSTI,
					Level:   LevelStrong,
					Reason:  "Template engine mathematical canary ({{…*…}})",
					Matched: snippet(v, start, end+2),
				}, true
			}
			return Detection{
				Module:  ModuleSSTI,
				Level:   LevelWeak,
				Reason:  "Template syntax in parameter",
				Matched: "{{",
			}, true
		}
	}

	// Twig block syntax {% raw %} / {% set %}
	if strings.Contains(lower, "{%") && strings.Contains(lower, "%}") {
		return Detection{
			Module:  ModuleSSTI,
			Level:   LevelWeak,
			Reason:  "Twig/Jinja block syntax in parameter",
			Matched: "{%",
		}, true
	}

	return Detection{}, false
}

// containsArithmetic reports whether the string contains multiplication,
// addition, or string-concat canary arithmetic typical of SSTI probes.
func containsArithmetic(s string) bool {
	// {{7*7}}, {{7*'7'}}, {{10+10}}, {{''.constructor')}}
	for _, r := range s {
		switch r {
		case '*', '+', '-', '/':
			return true
		}
	}
	return false
}

// PHP serialized payloads.
func scanPHPDeser(v string) (Detection, bool) {
	lower := strings.ToLower(v)

	// Serialized objects: O:<len>:"ClassName";N.. properties
	if idx := strings.Index(lower, "o:"); idx != -1 {
		if matchPHPObjectHeader(lower[idx+2:]) {
			return Detection{
				Module:  ModulePHPDeser,
				Level:   LevelStrong,
				Reason:  "PHP serialized object payload (O:<len>:)",
				Matched: snippet(v, idx, 12),
			}, true
		}
	}

	// Weak signal: array-styled serialized payloads (a:1:{s:...})
	if idx := strings.Index(lower, "a:"); idx != -1 {
		if matchPHPArrayHeader(lower[idx+2:]) {
			return Detection{
				Module:  ModulePHPDeser,
				Level:   LevelWeak,
				Reason:  "PHP serialized array payload",
				Matched: snippet(v, idx, 12),
			}, true
		}
	}

	return Detection{}, false
}

// matchPHPObjectHeader validates the `N:"Class"` shape after a leading `o:`.
func matchPHPObjectHeader(rest string) bool {
	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	if i == 0 || i > 10 {
		return false
	}
	if i >= len(rest) || rest[i] != ':' {
		return false
	}
	if i+1 < len(rest) && rest[i+1] == '"' {
		return true
	}
	return false
}

// matchPHPArrayHeader validates the `N:{` shape after a leading `a:`.
func matchPHPArrayHeader(rest string) bool {
	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	if i == 0 || i > 10 {
		return false
	}
	return i+1 < len(rest) && rest[i] == ':' && rest[i+1] == '{'
}

// snippet returns a bounded telemetry excerpt.
func snippet(v string, index, length int) string {
	const maxSnippet = 64
	if index >= len(v) {
		return ""
	}
	end := index + length
	if end > len(v) {
		end = len(v)
	}
	if end-index > maxSnippet {
		end = index + maxSnippet
	}
	return v[index:end]
}
