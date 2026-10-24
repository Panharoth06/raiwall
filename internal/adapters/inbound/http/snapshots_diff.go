package api

import (
	"fmt"
	"net/http"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// ConfigDiffItem describes an individual configuration entity difference.
type ConfigDiffItem struct {
	Type    string `json:"type"`   // site, exception, acl, policy
	Action  string `json:"action"` // added, modified, deleted
	Name    string `json:"name"`
	Details string `json:"details"`
}

// ConfigDiffResponse contains aggregated delta between staged and active configurations.
type ConfigDiffResponse struct {
	HasChanges    bool             `json:"has_changes"`
	ActiveVersion uint64           `json:"active_version"`
	StagedVersion uint64           `json:"staged_version"`
	Added         []string         `json:"added"`
	Modified      []string         `json:"modified"`
	Removed       []string         `json:"removed"`
	Diffs         []ConfigDiffItem `json:"diffs"`
	Summary       string           `json:"summary"`
}

func (s *Server) handleGetConfigDiff(w http.ResponseWriter, r *http.Request) {
	active := control.GetActiveSnapshot()
	staged, err := control.CompileSnapshot(r.Context(), s.store)
	if err != nil {
		respondError(w, http.StatusBadRequest, "pre-flight validation error in draft config: "+err.Error())
		return
	}

	var activeVer uint64
	if active != nil {
		activeVer = active.Version
	}

	added := make([]string, 0)
	modified := make([]string, 0)
	removed := make([]string, 0)
	diffItems := make([]ConfigDiffItem, 0)

	// Compare Apps
	if active != nil {
		for id, stagedApp := range staged.Apps {
			activeApp, exists := active.Apps[id]
			if !exists {
				msg := fmt.Sprintf("App: %s (%s)", stagedApp.Name, id)
				added = append(added, msg)
				diffItems = append(diffItems, ConfigDiffItem{
					Type:    "site",
					Action:  "added",
					Name:    stagedApp.Name,
					Details: fmt.Sprintf("Hostnames: %v, Mode: %s", stagedApp.Hostnames, stagedApp.Mode),
				})
			} else {
				if activeApp.Name != stagedApp.Name || activeApp.Mode != stagedApp.Mode || len(activeApp.Upstreams) != len(stagedApp.Upstreams) {
					msg := fmt.Sprintf("App: %s (%s)", stagedApp.Name, id)
					modified = append(modified, msg)
					diffItems = append(diffItems, ConfigDiffItem{
						Type:    "site",
						Action:  "modified",
						Name:    stagedApp.Name,
						Details: fmt.Sprintf("Mode: %s, Upstreams: %d", stagedApp.Mode, len(stagedApp.Upstreams)),
					})
				}
			}
		}
		for id, activeApp := range active.Apps {
			if _, exists := staged.Apps[id]; !exists {
				msg := fmt.Sprintf("App: %s (%s)", activeApp.Name, id)
				removed = append(removed, msg)
				diffItems = append(diffItems, ConfigDiffItem{
					Type:    "site",
					Action:  "deleted",
					Name:    activeApp.Name,
					Details: "Site removed from draft",
				})
			}
		}
	} else {
		for id, stagedApp := range staged.Apps {
			msg := fmt.Sprintf("App: %s (%s)", stagedApp.Name, id)
			added = append(added, msg)
			diffItems = append(diffItems, ConfigDiffItem{
				Type:    "site",
				Action:  "added",
				Name:    stagedApp.Name,
				Details: fmt.Sprintf("Hostnames: %v, Mode: %s", stagedApp.Hostnames, stagedApp.Mode),
			})
		}
	}

	// Compare Exceptions count
	activeExcCount := 0
	if active != nil {
		activeExcCount = len(active.Exceptions)
	}
	if len(staged.Exceptions) > activeExcCount {
		msg := fmt.Sprintf("%d new exception rule(s)", len(staged.Exceptions)-activeExcCount)
		added = append(added, msg)
		diffItems = append(diffItems, ConfigDiffItem{
			Type:    "exception",
			Action:  "added",
			Name:    "Exception Rules",
			Details: msg,
		})
	} else if len(staged.Exceptions) < activeExcCount {
		msg := fmt.Sprintf("%d exception rule(s) removed", activeExcCount-len(staged.Exceptions))
		removed = append(removed, msg)
		diffItems = append(diffItems, ConfigDiffItem{
			Type:    "exception",
			Action:  "deleted",
			Name:    "Exception Rules",
			Details: msg,
		})
	}

	// Compare ACLs count
	activeACLCount := 0
	if active != nil {
		activeACLCount = len(active.ACLRules)
	}
	if len(staged.ACLRules) > activeACLCount {
		msg := fmt.Sprintf("%d new ACL rule(s)", len(staged.ACLRules)-activeACLCount)
		added = append(added, msg)
		diffItems = append(diffItems, ConfigDiffItem{
			Type:    "acl",
			Action:  "added",
			Name:    "ACL Rules",
			Details: msg,
		})
	} else if len(staged.ACLRules) < activeACLCount {
		msg := fmt.Sprintf("%d ACL rule(s) removed", activeACLCount-len(staged.ACLRules))
		removed = append(removed, msg)
		diffItems = append(diffItems, ConfigDiffItem{
			Type:    "acl",
			Action:  "deleted",
			Name:    "ACL Rules",
			Details: msg,
		})
	}

	hasChanges := len(added) > 0 || len(modified) > 0 || len(removed) > 0
	summary := fmt.Sprintf("%d added, %d modified, %d removed", len(added), len(modified), len(removed))
	if !hasChanges {
		summary = "No staged changes detected. Staged draft matches active configuration."
	}

	respondJSON(w, http.StatusOK, ConfigDiffResponse{
		HasChanges:    hasChanges,
		ActiveVersion: activeVer,
		StagedVersion: staged.Version,
		Added:         added,
		Modified:      modified,
		Removed:       removed,
		Diffs:         diffItems,
		Summary:       summary,
	})
}
