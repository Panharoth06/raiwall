package control

import (
	"sort"
	"strings"
)

// RuleCatalogQuery filters a catalog listing.
type RuleCatalogQuery struct {
	Search   string
	Source   string
	Pack     string
	Category string
	Severity string
	Enabled  *bool
	Offset   int
	Limit    int
}

// RuleCatalogFacet is a filter chip value with its occurrence count.
type RuleCatalogFacet struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// RuleCatalogFacets are the available values for filtering.
type RuleCatalogFacets struct {
	Sources    []RuleCatalogFacet `json:"sources"`
	Categories []RuleCatalogFacet `json:"categories"`
	Severities []RuleCatalogFacet `json:"severities"`
	Packs      []RuleCatalogFacet `json:"packs"`
}

// FilterRuleCatalog applies query filters and returns the page plus facets.
func FilterRuleCatalog(items []RuleCatalogItem, query RuleCatalogQuery) ([]RuleCatalogItem, int, RuleCatalogFacets) {
	facets := buildFacets(items)
	search := strings.ToLower(strings.TrimSpace(query.Search))
	filtered := make([]RuleCatalogItem, 0, len(items))
	for _, item := range items {
		if query.Source != "" && item.Source != query.Source {
			continue
		}
		if query.Pack != "" && item.PackID != query.Pack {
			continue
		}
		if query.Category != "" && item.Category != query.Category {
			continue
		}
		if query.Severity != "" && item.Severity != query.Severity {
			continue
		}
		if query.Enabled != nil && item.Enabled != *query.Enabled {
			continue
		}
		if search != "" {
			haystack := strings.ToLower(item.ID + " " + item.Name + " " + item.Category + " " + item.PackName)
			if !strings.Contains(haystack, search) {
				continue
			}
		}
		filtered = append(filtered, item)
	}

	total := len(filtered)
	if query.Offset < 0 {
		query.Offset = 0
	}
	if query.Limit <= 0 || query.Limit > 200 {
		query.Limit = 50
	}
	if query.Offset >= total {
		return []RuleCatalogItem{}, total, facets
	}
	end := query.Offset + query.Limit
	if end > total {
		end = total
	}
	return filtered[query.Offset:end], total, facets
}

func buildFacets(items []RuleCatalogItem) RuleCatalogFacets {
	sources := map[string]int{}
	categories := map[string]int{}
	severities := map[string]int{}
	packs := map[string]int{}
	for _, item := range items {
		sources[item.Source]++
		categories[item.Category]++
		severities[item.Severity]++
		if item.PackID != "" {
			packs[item.PackID]++
		}
	}
	return RuleCatalogFacets{
		Sources:    sortedFacets(sources),
		Categories: sortedFacets(categories),
		Severities: sortedFacets(severities),
		Packs:      sortedFacets(packs),
	}
}

func sortedFacets(values map[string]int) []RuleCatalogFacet {
	out := make([]RuleCatalogFacet, 0, len(values))
	for value, count := range values {
		if value == "" {
			continue
		}
		out = append(out, RuleCatalogFacet{Value: value, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	return out
}
