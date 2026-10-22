package acl

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gaissmai/bart"
)

// BARTTable wraps a Balanced Routing Table (bart.Table) for sub-microsecond
// IP and CIDR prefix lookups across threat feeds.
// Read operations (Lookup, Contains, InFeed) are completely lock-free via atomic.Pointer.
type BARTTable struct {
	current atomic.Pointer[bart.Table[FeedMetadata]]
	mu      sync.Mutex
}

// NewBARTTable creates an empty initialized BARTTable.
func NewBARTTable() *BARTTable {
	b := &BARTTable{}
	b.current.Store(new(bart.Table[FeedMetadata]))
	return b
}

// NetipAddrFromIP converts a standard net.IP to netip.Addr with IPv4-in-IPv6 unmapping.
func NetipAddrFromIP(ip net.IP) (netip.Addr, bool) {
	if ip == nil {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// ParsePrefix parses an IP or CIDR notation string into a canonical netip.Prefix with unmapping.
func ParsePrefix(cidrOrIP string) (netip.Prefix, error) {
	cleaned := strings.TrimSpace(cidrOrIP)
	if cleaned == "" {
		return netip.Prefix{}, fmt.Errorf("empty CIDR or IP string")
	}

	if strings.Contains(cleaned, "/") {
		pfx, err := netip.ParsePrefix(cleaned)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR prefix %q: %w", cleaned, err)
		}
		addr := pfx.Addr()
		bits := pfx.Bits()
		if addr.Is4In6() {
			addr = addr.Unmap()
			if bits >= 96 {
				bits -= 96
			}
		}
		return netip.PrefixFrom(addr, bits), nil
	}

	addr, err := netip.ParseAddr(cleaned)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP address %q: %w", cleaned, err)
	}
	addr = addr.Unmap()
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits), nil
}

// ParseIPOrCIDR is an alias for ParsePrefix.
func ParseIPOrCIDR(cidrOrIP string) (netip.Prefix, error) {
	return ParsePrefix(cidrOrIP)
}

// UpdateTable atomically replaces the active routing table with newTable.
func (b *BARTTable) UpdateTable(newTable *bart.Table[FeedMetadata]) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if newTable == nil {
		newTable = new(bart.Table[FeedMetadata])
	}
	b.current.Store(newTable)
}

// Table returns the underlying *bart.Table snapshot for read operations.
func (b *BARTTable) Table() *bart.Table[FeedMetadata] {
	return b.current.Load()
}

// Insert registers a prefix under a designated feedName and description using copy-on-write.
func (b *BARTTable) Insert(pfx netip.Prefix, feedName string, desc string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	curr := b.current.Load()
	var newTable *bart.Table[FeedMetadata]
	if curr == nil {
		newTable = new(bart.Table[FeedMetadata])
	} else {
		newTable = curr.Clone()
	}

	newTable.Modify(pfx, func(existing FeedMetadata, ok bool) (FeedMetadata, bool) {
		if !ok {
			feeds := make([]string, 0, 1)
			if feedName != "" {
				feeds = append(feeds, feedName)
			}
			return FeedMetadata{
				Feeds:       feeds,
				Description: desc,
			}, false
		}

		// Append feedName if not present
		if feedName != "" && !existing.HasFeed(feedName) {
			existing.Feeds = append(existing.Feeds, feedName)
		}
		if desc != "" && existing.Description == "" {
			existing.Description = desc
		}
		return existing, false
	})

	b.current.Store(newTable)
}

// InsertCIDR parses a CIDR or IP string and inserts it into the table.
func (b *BARTTable) InsertCIDR(cidr string, feedName string, desc string) error {
	pfx, err := ParsePrefix(cidr)
	if err != nil {
		return err
	}
	b.Insert(pfx, feedName, desc)
	return nil
}

// InsertIP inserts a single net.IP into the table.
func (b *BARTTable) InsertIP(ip net.IP, feedName string, desc string) error {
	addr, ok := NetipAddrFromIP(ip)
	if !ok {
		return fmt.Errorf("invalid IP: %v", ip)
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	b.Insert(netip.PrefixFrom(addr, bits), feedName, desc)
	return nil
}

// BatchInsert inserts multiple prefixes under the same feedName and description in a single atomic update.
func (b *BARTTable) BatchInsert(prefixes []netip.Prefix, feedName string, desc string) {
	if len(prefixes) == 0 {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	curr := b.current.Load()
	var newTable *bart.Table[FeedMetadata]
	if curr == nil {
		newTable = new(bart.Table[FeedMetadata])
	} else {
		newTable = curr.Clone()
	}

	for _, pfx := range prefixes {
		newTable.Modify(pfx, func(existing FeedMetadata, ok bool) (FeedMetadata, bool) {
			if !ok {
				feeds := make([]string, 0, 1)
				if feedName != "" {
					feeds = append(feeds, feedName)
				}
				return FeedMetadata{
					Feeds:       feeds,
					Description: desc,
				}, false
			}

			if feedName != "" && !existing.HasFeed(feedName) {
				existing.Feeds = append(existing.Feeds, feedName)
			}
			if desc != "" && existing.Description == "" {
				existing.Description = desc
			}
			return existing, false
		})
	}

	b.current.Store(newTable)
}

// Delete removes a prefix from the designated feedName. If feedName is empty or after removal no feeds remain, the prefix is removed from the table entirely.
func (b *BARTTable) Delete(pfx netip.Prefix, feedName string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	curr := b.current.Load()
	if curr == nil {
		return
	}
	newTable := curr.Clone()
	newTable.Modify(pfx, func(existing FeedMetadata, ok bool) (FeedMetadata, bool) {
		if !ok {
			return existing, false
		}
		if feedName == "" {
			return existing, true // delete entirely
		}
		updatedFeeds := make([]string, 0, len(existing.Feeds))
		for _, f := range existing.Feeds {
			if f != feedName {
				updatedFeeds = append(updatedFeeds, f)
			}
		}
		if len(updatedFeeds) == 0 {
			return existing, true // delete entry from table
		}
		existing.Feeds = updatedFeeds
		return existing, false
	})
	b.current.Store(newTable)
}

// DeleteCIDR parses a CIDR or IP string and deletes it from the table for the feedName.
func (b *BARTTable) DeleteCIDR(cidr string, feedName string) error {
	pfx, err := ParsePrefix(cidr)
	if err != nil {
		return err
	}
	b.Delete(pfx, feedName)
	return nil
}

// LookupAddr retrieves the FeedMetadata for a netip.Addr in sub-microsecond time.
func (b *BARTTable) LookupAddr(addr netip.Addr) (FeedMetadata, bool) {
	t := b.current.Load()
	if t == nil {
		return FeedMetadata{}, false
	}
	return t.Lookup(addr.Unmap())
}

// Lookup retrieves the FeedMetadata for a net.IP.
func (b *BARTTable) Lookup(ip net.IP) (FeedMetadata, bool) {
	addr, ok := NetipAddrFromIP(ip)
	if !ok {
		return FeedMetadata{}, false
	}
	return b.LookupAddr(addr)
}

// ContainsAddr checks if a netip.Addr matches any prefix in the routing table.
func (b *BARTTable) ContainsAddr(addr netip.Addr) bool {
	t := b.current.Load()
	if t == nil {
		return false
	}
	return t.Contains(addr.Unmap())
}

// Contains checks if a net.IP matches any prefix in the routing table.
func (b *BARTTable) Contains(ip net.IP) bool {
	addr, ok := NetipAddrFromIP(ip)
	if !ok {
		return false
	}
	return b.ContainsAddr(addr)
}

// InFeedAddr checks if a netip.Addr belongs to a specific threat feed (or any feed if feedName is empty or "*").
func (b *BARTTable) InFeedAddr(addr netip.Addr, feedName string) bool {
	entry, ok := b.LookupAddr(addr)
	if !ok {
		return false
	}
	return entry.HasFeed(feedName)
}

// InFeed checks if a net.IP belongs to a specific threat feed.
func (b *BARTTable) InFeed(ip net.IP, feedName string) bool {
	addr, ok := NetipAddrFromIP(ip)
	if !ok {
		return false
	}
	return b.InFeedAddr(addr, feedName)
}

// Size returns the total number of prefixes registered in the routing table.
func (b *BARTTable) Size() int {
	t := b.current.Load()
	if t == nil {
		return 0
	}
	return t.Size()
}

// InCIDR checks if an IP belongs to a specified CIDR subnet.
func InCIDR(ip net.IP, cidr string) bool {
	addr, ok := NetipAddrFromIP(ip)
	if !ok {
		return false
	}
	return InCIDRAddr(addr, cidr)
}

// InCIDRAddr checks if a netip.Addr belongs to a specified CIDR subnet.
func InCIDRAddr(addr netip.Addr, cidr string) bool {
	pfx, err := ParsePrefix(cidr)
	if err != nil {
		return false
	}
	return pfx.Contains(addr.Unmap())
}
