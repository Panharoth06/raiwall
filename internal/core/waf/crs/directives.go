package crs

import (
	"fmt"
	"sort"
	"strings"
)

// directives builds the Coraza ruleset: Raiwall setup actions, the embedded
// CRS (unless replaced), imported packs, then per-rule removals and severity
// updates. Update directives are emitted only for rules that exist, because
// Coraza rejects updates for unknown IDs.
func directives(conf Config) string {
	var b strings.Builder
	b.WriteString("SecRuleEngine On\n")
	fmt.Fprintf(&b, `
SecAction "id:990000,phase:1,pass,nolog,t:none,tag:'OWASP_CRS',setvar:tx.blocking_paranoia_level=%d"
SecAction "id:990001,phase:1,pass,nolog,t:none,tag:'OWASP_CRS',setvar:tx.detection_paranoia_level=%d"
SecAction "id:990110,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold=%d"
SecAction "id:990120,phase:1,pass,nolog,t:none,setvar:tx.outbound_anomaly_score_threshold=%d"
`, conf.ParanoiaLevel, conf.ParanoiaLevel, conf.InboundThreshold, conf.OutboundThreshold)

	replaceBuiltin := false
	for _, pack := range conf.Packs {
		if pack.ReplaceBuiltin {
			replaceBuiltin = true
		}
	}
	known := make(map[int]struct{})
	if !replaceBuiltin {
		b.WriteString("Include crs-setup.conf\n")
		b.WriteString("Include rules/REQUEST-*.conf\n")
		b.WriteString("Include rules/RESPONSE-*.conf\n")
		if metadata, err := EmbeddedRuleMetadata(); err == nil {
			for _, meta := range metadata {
				known[meta.ID] = struct{}{}
			}
		}
	}

	packs := append([]Pack(nil), conf.Packs...)
	sort.SliceStable(packs, func(i, j int) bool { return packs[i].ID < packs[j].ID })
	for _, pack := range packs {
		prefix := "packs/" + safePackID(pack.ID) + "/"
		paths := make([]string, 0, len(pack.Files))
		for name := range pack.Files {
			if strings.HasSuffix(strings.ToLower(name), ".conf") {
				paths = append(paths, name)
			}
		}
		sort.Strings(paths)
		for _, name := range paths {
			fmt.Fprintf(&b, "Include %s%s\n", prefix, name)
		}
		if strings.TrimSpace(pack.Directives) != "" {
			b.WriteString(pack.Directives)
			b.WriteString("\n")
		}
		for _, meta := range scanPackMetadata(pack) {
			known[meta.ID] = struct{}{}
		}
	}

	for _, override := range conf.Overrides {
		if override.Disabled {
			fmt.Fprintf(&b, "SecRuleRemoveById %d\n", override.RuleID)
			continue
		}
		severity := normalizeSeverity(override.Severity)
		if severity == "" {
			continue
		}
		if _, ok := known[override.RuleID]; !ok {
			continue
		}
		fmt.Fprintf(&b, "SecRuleUpdateActionById %d \"severity:'%s'\"\n", override.RuleID, severity)
	}
	return b.String()
}

func scanPackMetadata(pack Pack) []RuleMeta {
	meta := ScanDirectiveMetadata(pack.Directives)
	for name, content := range pack.Files {
		if !strings.HasSuffix(strings.ToLower(name), ".conf") {
			continue
		}
		meta = append(meta, ScanDirectiveMetadata(content)...)
	}
	return meta
}

// normalizeSeverity maps Raiwall's catalog scale onto ModSecurity severity
// names. Coraza rejects unknown values, so the mapping is explicit.
func normalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high":
		return "CRITICAL"
	case "medium":
		return "WARNING"
	case "low":
		return "NOTICE"
	default:
		return ""
	}
}
