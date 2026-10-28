package declarative

import (
	"fmt"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/config"
	"github.com/Panharoth06/raiwall/internal/core/control"
)

// syncExceptions materializes parameter-level false-positive exceptions.
func (s *syncer) syncExceptions(exceptions []config.Exception) error {
	existing, err := s.store.ListExceptions(s.ctx)
	if err != nil {
		return err
	}
	byID := make(map[string]control.ExceptionRule, len(existing))
	ids := make([]string, 0, len(existing))
	for _, rec := range existing {
		byID[rec.ID] = rec
		ids = append(ids, rec.ID)
	}

	declared := make(map[string]struct{}, len(exceptions))
	for i, exc := range exceptions {
		id := exceptionID(exc, i)
		declared[id] = struct{}{}

		prev, exists := byID[id]
		if exists && !s.canWrite(true) {
			continue
		}
		pathPrefix := strings.TrimSpace(exc.PathPrefix)
		if pathPrefix == "" {
			pathPrefix = strings.TrimSpace(exc.Path)
		}
		now := time.Now().UTC()
		rec := control.ExceptionRule{
			ID:          id,
			Description: exc.Description,
			Host:        strings.TrimSpace(exc.Host),
			PathRegex:   exc.PathRegex,
			PathPrefix:  pathPrefix,
			Method:      strings.ToUpper(strings.TrimSpace(exc.Method)),
			Location:    exc.Location,
			ParamName:   exc.ParamName,
			ParamRegex:  exc.ParamRegex,
			RuleID:      exc.RuleID,
			IsActive:    boolToInt(enabled(exc.Enabled)),
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if !prev.CreatedAt.IsZero() {
			rec.CreatedAt = prev.CreatedAt
		}
		if exists {
			if sameException(prev, rec) {
				continue
			}
			if err := s.store.UpdateException(s.ctx, rec); err != nil {
				if ferr := s.handle("exception", id, err); ferr != nil {
					return ferr
				}
				continue
			}
			s.result.Updated++
			continue
		}
		if err := s.store.CreateException(s.ctx, rec); err != nil {
			if ferr := s.handle("exception", id, err); ferr != nil {
				return ferr
			}
			continue
		}
		s.result.Created++
	}

	return s.pruneIDs(KindException, declared, ids, func(id string) error {
		return s.store.DeleteException(s.ctx, id)
	})
}

func exceptionID(exc config.Exception, index int) string {
	if strings.TrimSpace(exc.Name) != "" {
		return namedID(KindException, exc.Name)
	}
	return hashedID(KindException,
		strings.ToLower(exc.Host), exc.Path, exc.PathPrefix, exc.PathRegex,
		strings.ToUpper(exc.Method), exc.Location, exc.ParamName, exc.ParamRegex, exc.RuleID)
}

// syncACLs materializes compiled boolean access-control rules.
func (s *syncer) syncACLs(rules []config.ACLRule) error {
	existing, err := s.store.ListACLRules(s.ctx)
	if err != nil {
		return err
	}
	byID := make(map[string]control.AclRule, len(existing))
	byName := make(map[string]control.AclRule, len(existing))
	ids := make([]string, 0, len(existing))
	for _, rec := range existing {
		byID[rec.ID] = rec
		byName[rec.Name] = rec
		ids = append(ids, rec.ID)
	}

	declared := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		id := namedID(KindACL, rule.Name)
		declared[id] = struct{}{}

		prev, exists := byID[id]
		if !exists {
			if other, taken := byName[rule.Name]; taken && !IsManaged(other.ID) {
				if err := s.conflict("ACL rule", rule.Name); err != nil {
					return err
				}
				continue
			}
		}
		if exists && !s.canWrite(true) {
			continue
		}

		now := time.Now().UTC()
		rec := control.AclRule{
			ID:                 id,
			Name:               rule.Name,
			Expression:         rule.Expression,
			Action:             strings.ToLower(rule.Action),
			Priority:           rule.Priority,
			StatusCode:         rule.StatusCode,
			RedirectUrl:        rule.RedirectURL,
			IsActive:           boolToInt(enabled(rule.Enabled)),
			ContinueInspection: boolToInt(rule.ContinueInspection != nil && *rule.ContinueInspection),
			CreatedAt:          now,
			UpdatedAt:          now,
		}
		if !prev.CreatedAt.IsZero() {
			rec.CreatedAt = prev.CreatedAt
		}
		if exists {
			if sameACL(prev, rec) {
				continue
			}
			if err := s.store.UpdateACLRule(s.ctx, rec); err != nil {
				if ferr := s.handle("ACL rule", rule.Name, err); ferr != nil {
					return ferr
				}
				continue
			}
			s.result.Updated++
			continue
		}
		if err := s.store.CreateACLRule(s.ctx, rec); err != nil {
			if ferr := s.handle("ACL rule", rule.Name, err); ferr != nil {
				return ferr
			}
			continue
		}
		s.result.Created++
	}

	return s.pruneIDs(KindACL, declared, ids, func(id string) error {
		return s.store.DeleteACLRule(s.ctx, id)
	})
}

// syncIPGroups materializes named CIDR collections and reconciles their entries.
func (s *syncer) syncIPGroups(groups []config.IPGroup) error {
	existing, err := s.store.ListIPGroups(s.ctx)
	if err != nil {
		return err
	}
	byID := make(map[string]control.IPGroupRecord, len(existing))
	byName := make(map[string]control.IPGroupRecord, len(existing))
	ids := make([]string, 0, len(existing))
	for _, rec := range existing {
		byID[rec.ID] = rec
		byName[rec.Name] = rec
		ids = append(ids, rec.ID)
	}

	declared := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		id := namedID(KindIPGroup, group.Name)
		declared[id] = struct{}{}

		prev, exists := byID[id]
		if !exists {
			if other, taken := byName[group.Name]; taken && !IsManaged(other.ID) {
				if err := s.conflict("IP group", group.Name); err != nil {
					return err
				}
				continue
			}
		}
		if exists && !s.canWrite(true) {
			continue
		}

		now := time.Now().UTC()
		rec := control.IPGroupRecord{
			ID:          id,
			Name:        group.Name,
			Description: group.Description,
			Type:        "manual",
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if !prev.CreatedAt.IsZero() {
			rec.CreatedAt = prev.CreatedAt
		}
		if prev.Type != "" {
			rec.Type = prev.Type
		}
		if exists {
			if prev.Name != rec.Name || prev.Description != rec.Description {
				if err := s.store.UpdateIPGroup(s.ctx, rec); err != nil {
					if ferr := s.handle("IP group", group.Name, err); ferr != nil {
						return ferr
					}
					continue
				}
				s.result.Updated++
			}
		} else {
			if err := s.store.CreateIPGroup(s.ctx, rec); err != nil {
				if ferr := s.handle("IP group", group.Name, err); ferr != nil {
					return ferr
				}
				continue
			}
			s.result.Created++
		}

		if err := s.syncIPGroupEntries(id, group.Entries); err != nil {
			if ferr := s.handle("IP group entries", group.Name, err); ferr != nil {
				return ferr
			}
		}
	}

	return s.pruneIDs(KindIPGroup, declared, ids, func(id string) error {
		return s.store.DeleteIPGroup(s.ctx, id)
	})
}

func (s *syncer) syncIPGroupEntries(groupID string, entries []config.IPGroupEntry) error {
	existing, err := s.store.ListIPGroupEntries(s.ctx, groupID)
	if err != nil {
		return err
	}
	keep := make(map[string]string, len(entries))
	for _, entry := range entries {
		cidr := strings.TrimSpace(entry.CIDR)
		if cidr == "" {
			continue
		}
		keep[cidr] = entry.Comment
	}

	present := make(map[string]control.IPGroupEntryRecord, len(existing))
	for _, rec := range existing {
		if _, wanted := keep[rec.CIDR]; !wanted {
			if err := s.store.DeleteIPGroupEntry(s.ctx, rec.ID); err != nil {
				return err
			}
			s.result.Deleted++
			continue
		}
		present[rec.CIDR] = rec
	}

	for cidr, comment := range keep {
		if rec, ok := present[cidr]; ok {
			if rec.Comment == comment {
				continue
			}
			// Entries are immutable; replace to pick up the new comment.
			if err := s.store.DeleteIPGroupEntry(s.ctx, rec.ID); err != nil {
				return err
			}
			s.result.Deleted++
		}
		if err := s.store.CreateIPGroupEntry(s.ctx, control.IPGroupEntryRecord{
			ID:        hashedID("ip_group_entry", groupID, cidr),
			GroupID:   groupID,
			CIDR:      cidr,
			Comment:   comment,
			CreatedAt: time.Now().UTC(),
		}); err != nil {
			return fmt.Errorf("create entry %s: %w", cidr, err)
		}
		s.result.Created++
	}
	return nil
}

func sameException(a, b control.ExceptionRule) bool {
	return a.Description == b.Description && a.Host == b.Host && a.PathRegex == b.PathRegex &&
		a.PathPrefix == b.PathPrefix && a.Method == b.Method && a.Location == b.Location &&
		a.ParamName == b.ParamName && a.ParamRegex == b.ParamRegex && a.RuleID == b.RuleID &&
		a.IsActive == b.IsActive
}

func sameACL(a, b control.AclRule) bool {
	return a.Name == b.Name && a.Expression == b.Expression && a.Action == b.Action &&
		a.Priority == b.Priority && a.StatusCode == b.StatusCode &&
		a.RedirectUrl == b.RedirectUrl && a.IsActive == b.IsActive &&
		a.ContinueInspection == b.ContinueInspection
}

func enabled(v *bool) bool { return v == nil || *v }
