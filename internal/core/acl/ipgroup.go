package acl

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// IPGroup represents a named IP group metadata record.
type IPGroup struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Type        string    `json:"type"` // "system", "custom", "threat_feed"
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// IPGroupEntry represents an individual CIDR or IP registered in a named IP group.
type IPGroupEntry struct {
	ID        string    `json:"id"`
	GroupID   string    `json:"group_id"`
	CIDR      string    `json:"cidr"`
	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"created_at"`
}

// IPGroupRef is passed into expr evaluation context to support `client_ip in ip_group("...")`.
type IPGroupRef struct {
	Name    string
	manager *IPGroupManager
}

// Contains checks if the IP address belongs to this named IP group.
func (r IPGroupRef) Contains(ipStr string) bool {
	if r.manager == nil {
		return false
	}
	return r.manager.InGroupStr(ipStr, r.Name)
}

// IPGroupManager manages in-memory named IP groups backed by BART for sub-15 ns evaluation.
type IPGroupManager struct {
	mu      sync.RWMutex
	table   *BARTTable
	groups  map[string]*IPGroup        // Keyed by ID and Name
	entries map[string][]*IPGroupEntry // Keyed by Group ID
}

// NewIPGroupManager initializes a new IPGroupManager.
func NewIPGroupManager(table *BARTTable) *IPGroupManager {
	if table == nil {
		table = NewBARTTable()
	}
	mgr := &IPGroupManager{
		table:   table,
		groups:  make(map[string]*IPGroup),
		entries: make(map[string][]*IPGroupEntry),
	}
	mgr.PopulateBuiltins()
	return mgr
}

// Table returns the underlying BARTTable.
// CleanIP parses an IP address string, stripping any port and trimming whitespace.
func CleanIP(s string) net.IP {
	s = strings.TrimSpace(s)
	if idx := strings.IndexByte(s, ','); idx != -1 {
		s = strings.TrimSpace(s[:idx])
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	return net.ParseIP(s)
}

// Table returns the underlying BARTTable.
func (m *IPGroupManager) Table() *BARTTable {
	return m.table
}

// EnsureGroup creates a group if it doesn't exist, or returns the existing group.
func (m *IPGroupManager) EnsureGroup(id, name, description, groupType string) *IPGroup {
	m.mu.Lock()
	defer m.mu.Unlock()

	if grp, exists := m.groups[name]; exists {
		return grp
	}
	if id != "" {
		if grp, exists := m.groups[id]; exists {
			return grp
		}
	}

	if id == "" {
		id = uuid.New().String()
	}
	if groupType == "" {
		groupType = "custom"
	}
	now := time.Now().UTC()
	grp := &IPGroup{
		ID:          id,
		Name:        name,
		Description: description,
		Type:        groupType,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	m.groups[grp.ID] = grp
	m.groups[grp.Name] = grp
	m.entries[grp.ID] = make([]*IPGroupEntry, 0)
	return grp
}

// CreateGroup creates a new named IP group.
func (m *IPGroupManager) CreateGroup(name, description, groupType string) (*IPGroup, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("group name cannot be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.groups[name]; exists {
		return nil, fmt.Errorf("ip group %q already exists", name)
	}

	if groupType == "" {
		groupType = "custom"
	}

	now := time.Now().UTC()
	grp := &IPGroup{
		ID:          uuid.New().String(),
		Name:        name,
		Description: description,
		Type:        groupType,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	m.groups[grp.ID] = grp
	m.groups[grp.Name] = grp
	m.entries[grp.ID] = make([]*IPGroupEntry, 0)
	return grp, nil
}

// GetGroup retrieves an IP group by its ID or Name.
func (m *IPGroupManager) GetGroup(nameOrID string) (*IPGroup, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	grp, ok := m.groups[nameOrID]
	return grp, ok
}

// ListGroups returns all registered IP groups.
func (m *IPGroupManager) ListGroups() []*IPGroup {
	m.mu.RLock()
	defer m.mu.RUnlock()

	seen := make(map[string]bool)
	result := make([]*IPGroup, 0, len(m.groups))
	for _, grp := range m.groups {
		if !seen[grp.ID] {
			seen[grp.ID] = true
			result = append(result, grp)
		}
	}
	return result
}

// DeleteGroup removes an IP group and all its entries from memory and the BART table.
func (m *IPGroupManager) DeleteGroup(nameOrID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	grp, ok := m.groups[nameOrID]
	if !ok {
		return fmt.Errorf("group %q not found", nameOrID)
	}

	entries := m.entries[grp.ID]
	for _, e := range entries {
		_ = m.table.DeleteCIDR(e.CIDR, grp.Name)
	}

	delete(m.groups, grp.ID)
	delete(m.groups, grp.Name)
	delete(m.entries, grp.ID)
	return nil
}

// AddCIDR adds a CIDR prefix to the specified IP group and registers it in the BART table.
func (m *IPGroupManager) AddCIDR(nameOrID, cidr, comment string) (*IPGroupEntry, error) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return nil, fmt.Errorf("cidr cannot be empty")
	}

	pfx, err := ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR prefix %q: %w", cidr, err)
	}
	canonicalCIDR := pfx.String()

	m.mu.Lock()
	defer m.mu.Unlock()

	grp, ok := m.groups[nameOrID]
	if !ok {
		return nil, fmt.Errorf("group %q not found", nameOrID)
	}

	// Check duplicate in this group
	for _, existing := range m.entries[grp.ID] {
		if existing.CIDR == canonicalCIDR {
			return existing, nil
		}
	}

	entry := &IPGroupEntry{
		ID:        uuid.New().String(),
		GroupID:   grp.ID,
		CIDR:      canonicalCIDR,
		Comment:   comment,
		CreatedAt: time.Now().UTC(),
	}

	if err := m.table.InsertCIDR(canonicalCIDR, grp.Name, comment); err != nil {
		return nil, fmt.Errorf("insert into BART table: %w", err)
	}

	m.entries[grp.ID] = append(m.entries[grp.ID], entry)
	grp.UpdatedAt = time.Now().UTC()
	return entry, nil
}

// RemoveCIDR removes a CIDR prefix from an IP group and updates the BART table.
func (m *IPGroupManager) RemoveCIDR(nameOrID, cidrOrEntryID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	grp, ok := m.groups[nameOrID]
	if !ok {
		return fmt.Errorf("group %q not found", nameOrID)
	}

	entries := m.entries[grp.ID]
	var removedCIDR string
	newEntries := make([]*IPGroupEntry, 0, len(entries))

	for _, e := range entries {
		if e.ID == cidrOrEntryID || e.CIDR == cidrOrEntryID {
			removedCIDR = e.CIDR
		} else {
			newEntries = append(newEntries, e)
		}
	}

	if removedCIDR == "" {
		return fmt.Errorf("entry %q not found in group %q", cidrOrEntryID, grp.Name)
	}

	_ = m.table.DeleteCIDR(removedCIDR, grp.Name)
	m.entries[grp.ID] = newEntries
	grp.UpdatedAt = time.Now().UTC()
	return nil
}

// ListEntries returns all CIDR entries in a group.
func (m *IPGroupManager) ListEntries(nameOrID string) []*IPGroupEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	grp, ok := m.groups[nameOrID]
	if !ok {
		return nil
	}
	entries := m.entries[grp.ID]
	cp := make([]*IPGroupEntry, len(entries))
	copy(cp, entries)
	return cp
}

// InGroup checks if an IP belongs to the named IP group.
func (m *IPGroupManager) InGroup(ip net.IP, groupName string) bool {
	if m == nil || m.table == nil || ip == nil {
		return false
	}
	return m.table.InFeed(ip, groupName)
}

// InGroupStr checks if an IP string belongs to the named IP group.
func (m *IPGroupManager) InGroupStr(ipStr, groupName string) bool {
	if m == nil || m.table == nil {
		return false
	}
	ip := CleanIP(ipStr)
	if ip == nil {
		return false
	}
	return m.table.InFeed(ip, groupName)
}

// Ref creates an IPGroupRef for expression evaluation.
func (m *IPGroupManager) Ref(name string) IPGroupRef {
	return IPGroupRef{
		Name:    name,
		manager: m,
	}
}

// PopulateBuiltins populates default system groups (Search Spiders, Malicious Threat Intel).
func (m *IPGroupManager) PopulateBuiltins() {
	// 1. Search Spiders Group
	spiders, _ := m.CreateGroup("search_spiders", "Verified Search Engine Spider Subnets", "system")
	spiderCIDRs := []string{
		// Googlebot
		"66.249.64.0/19", "64.233.160.0/19", "66.102.0.0/20", "72.14.192.0/18",
		"74.125.0.0/16", "209.85.128.0/17", "216.239.32.0/19",
		// Bingbot
		"157.55.39.0/24", "207.46.13.0/24", "40.77.167.0/24", "13.66.139.0/24", "13.67.10.0/24",
		// Baiduspider
		"180.76.0.0/16", "123.125.71.0/24", "220.181.108.0/24",
	}
	if spiders != nil {
		for _, c := range spiderCIDRs {
			_, _ = m.AddCIDR(spiders.ID, c, "Verified search crawler")
		}
	}

	// 2. Malicious Threat Intelligence Group
	threats, _ := m.CreateGroup("malicious_threat_intel", "Active Threat Intelligence Feeds", "system")
	threatCIDRs := []string{
		"185.220.101.0/24", "185.100.87.0/24", "45.154.255.0/24",
		"194.26.29.0/24", "89.248.165.0/24", "193.32.162.0/24",
	}
	if threats != nil {
		for _, c := range threatCIDRs {
			_, _ = m.AddCIDR(threats.ID, c, "High confidence malicious subnet")
		}
	}
}

// PopulateSyntheticThreats loads count IPs into malicious_threat_intel for high-scale benchmarks.
func (m *IPGroupManager) PopulateSyntheticThreats(count int) {
	grp, ok := m.GetGroup("malicious_threat_intel")
	if !ok || grp == nil {
		return
	}

	prefixes := make([]netip.Prefix, 0, count)
	for i := 0; i < count; i++ {
		b2 := byte(18 + (i / 65536))
		b3 := byte((i / 256) % 256)
		b4 := byte(i % 256)
		addr := netip.AddrFrom4([4]byte{198, b2, b3, b4})
		prefixes = append(prefixes, netip.PrefixFrom(addr, 32))
	}
	m.table.BatchInsert(prefixes, grp.Name, "Synthetic threat IP")
}
