package crs

import (
	"fmt"
	"strconv"

	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	ctypes "github.com/corazawaf/coraza/v3/types"
)

func verdict(set *compiledSet, tx ctypes.Transaction, it *ctypes.Interruption) *waf.Verdict {
	action := waf.ActionBlock
	if set.conf.Mode == ModeAudit {
		action = waf.ActionAudit
	}
	if action == waf.ActionBlock && set.alertOnly(tx, it) {
		action = waf.ActionAudit
	}

	v := &waf.Verdict{
		Action:         action,
		RuleID:         fmt.Sprintf("CRS_%d", it.RuleID),
		Reason:         fmt.Sprintf("OWASP CRS rule %d (%s)", it.RuleID, it.Action),
		AttackCategory: "crs",
		Engine:         "crs",
		Severity:       verdictSeverity(set, tx, it),
		AnomalyScore:   anomalyScore(tx),
		ParanoiaLevel:  set.conf.ParanoiaLevel,
	}
	if it.Status > 0 {
		v.StatusCode = it.Status
	}

	for _, match := range tx.MatchedRules() {
		meta := match.Rule()
		severity := meta.Severity().String()
		if override, ok := set.severity[meta.ID()]; ok {
			severity = override
		}
		// Setup and initialization rules have no severity and match on every
		// transaction; keep only detection rules and the interrupting rule so
		// the matched-rule list is actionable.
		if severity == "unknown" && meta.ID() != it.RuleID {
			continue
		}
		v.MatchedRules = append(v.MatchedRules, waf.RuleMatch{
			RuleID:   strconv.Itoa(meta.ID()),
			Message:  match.Message(),
			Severity: severity,
			Engine:   "crs",
		})
		if len(v.MatchedRules) >= MaxMatchedRules {
			break
		}
	}
	return v
}

// verdictSeverity uses the interrupting rule's severity, falling back to the
// highest detection severity in the transaction.
func verdictSeverity(set *compiledSet, tx ctypes.Transaction, it *ctypes.Interruption) string {
	if severity, ok := set.severity[it.RuleID]; ok {
		return severity
	}
	best := ""
	for _, match := range tx.MatchedRules() {
		meta := match.Rule()
		severity := meta.Severity().String()
		if override, ok := set.severity[meta.ID()]; ok {
			severity = override
		}
		if severity == "" || severity == "unknown" {
			continue
		}
		if meta.ID() == it.RuleID {
			return severity
		}
		if best == "" {
			best = severity
		}
	}
	if best != "" {
		return best
	}
	return "critical"
}

// alertOnly reports whether every detection rule that contributed to this
// transaction is configured alert-only. Anomaly aggregate rules are ignored.
func (s *compiledSet) alertOnly(tx ctypes.Transaction, it *ctypes.Interruption) bool {
	if len(s.alert) == 0 {
		return false
	}
	if _, ok := s.alert[it.RuleID]; ok {
		return true
	}
	contributors := 0
	for _, match := range tx.MatchedRules() {
		id := match.Rule().ID()
		if id == it.RuleID || id == 949110 || id == 959100 {
			continue
		}
		if match.Rule().Severity().String() == "unknown" {
			continue
		}
		contributors++
		if _, ok := s.alert[id]; !ok {
			return false
		}
	}
	return contributors > 0
}

// txVariables is implemented by Coraza's concrete transaction. The public
// types.Transaction interface does not expose variables, but the method set
// does, so a narrow assertion reads the anomaly score without importing
// Coraza internals.
type txVariables interface {
	Variables() plugintypes.TransactionVariables
}

func anomalyScore(tx ctypes.Transaction) float64 {
	vars, ok := tx.(txVariables)
	if !ok {
		return 0
	}
	txVars := vars.Variables().TX()
	for _, key := range []string{
		"blocking_inbound_anomaly_score",
		"blocking_outbound_anomaly_score",
		"outbound_anomaly_score",
		"anomaly_score",
	} {
		values := txVars.Get(key)
		if len(values) == 0 {
			continue
		}
		score, err := strconv.ParseFloat(values[0], 64)
		if err == nil {
			return score
		}
	}
	return 0
}
