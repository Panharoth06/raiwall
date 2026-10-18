package acl

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
)

func TestBARTTable_BasicAndCIDR(t *testing.T) {
	bt := NewBARTTable()

	// Insert IPv4 CIDR and single IP
	if err := bt.InsertCIDR("192.168.1.0/24", "crowdsec", "local test subnet"); err != nil {
		t.Fatalf("InsertCIDR error: %v", err)
	}
	if err := bt.InsertCIDR("10.0.0.1", "spamhaus", "bad host"); err != nil {
		t.Fatalf("InsertCIDR error: %v", err)
	}

	// Insert IPv6 CIDR
	if err := bt.InsertCIDR("2001:db8::/32", "tor", "tor exit prefix"); err != nil {
		t.Fatalf("InsertCIDR error: %v", err)
	}

	// Also insert crowdsec for the same 10.0.0.1 (multi-feed support)
	if err := bt.InsertCIDR("10.0.0.1/32", "crowdsec", "crowdsec crawler"); err != nil {
		t.Fatalf("InsertCIDR error: %v", err)
	}

	// Verify lookups
	ip1 := net.ParseIP("192.168.1.55")
	if !bt.Contains(ip1) {
		t.Errorf("expected 192.168.1.55 to be contained")
	}
	if !bt.InFeed(ip1, "crowdsec") {
		t.Errorf("expected 192.168.1.55 to be in crowdsec")
	}
	if bt.InFeed(ip1, "spamhaus") {
		t.Errorf("did not expect 192.168.1.55 to be in spamhaus")
	}

	// 10.0.0.1 has both spamhaus and crowdsec
	ip2 := net.ParseIP("10.0.0.1")
	entry, ok := bt.Lookup(ip2)
	if !ok {
		t.Fatalf("expected 10.0.0.1 to be found in table")
	}
	if len(entry.Feeds) != 2 {
		t.Errorf("expected 2 feeds for 10.0.0.1, got %v", entry.Feeds)
	}
	if !bt.InFeed(ip2, "spamhaus") || !bt.InFeed(ip2, "crowdsec") {
		t.Errorf("expected 10.0.0.1 in spamhaus and crowdsec")
	}

	// IPv6 lookup
	ip6 := net.ParseIP("2001:db8:85a3::8a2e:370:7334")
	if !bt.Contains(ip6) {
		t.Errorf("expected IPv6 to be contained")
	}
	if !bt.InFeed(ip6, "tor") {
		t.Errorf("expected IPv6 to be in tor")
	}

	// InCIDR standalone helpers
	if !InCIDR(ip1, "192.168.1.0/24") {
		t.Errorf("expected 192.168.1.55 to be in 192.168.1.0/24")
	}
	if InCIDR(net.ParseIP("172.16.0.1"), "192.168.1.0/24") {
		t.Errorf("did not expect 172.16.0.1 in 192.168.1.0/24")
	}

	// IPv4-mapped IPv6 support
	mappedIP := net.ParseIP("::ffff:192.168.1.55")
	if !bt.Contains(mappedIP) {
		t.Errorf("expected ::ffff:192.168.1.55 to be contained")
	}
	if !bt.InFeed(mappedIP, "crowdsec") {
		t.Errorf("expected ::ffff:192.168.1.55 to be in crowdsec")
	}

	// Insert IPv4-mapped IPv6 CIDR prefix
	if err := bt.InsertCIDR("::ffff:203.0.113.0/120", "mapped_feed", "ipv4 mapped subnet"); err != nil {
		t.Fatalf("InsertCIDR IPv4-mapped error: %v", err)
	}
	if !bt.InFeed(net.ParseIP("203.0.113.42"), "mapped_feed") {
		t.Errorf("expected 203.0.113.42 to match mapped_feed")
	}
	if !bt.InFeed(net.ParseIP("::ffff:203.0.113.42"), "mapped_feed") {
		t.Errorf("expected ::ffff:203.0.113.42 to match mapped_feed")
	}

	// Negative lookup
	ipOutside := net.ParseIP("172.16.0.1")
	if bt.Contains(ipOutside) {
		t.Errorf("did not expect 172.16.0.1 to be contained")
	}
}

func TestBARTTable_FeedLoader(t *testing.T) {
	feedData := `
# CrowdSec Threat List
185.220.101.5 # Tor exit node
185.220.101.6
// Another comment
198.51.100.0/24; trailing comment
invalid-line-to-skip
2001:db8:1::/48
`
	bt := NewBARTTable()
	n, err := LoadFeed(strings.NewReader(feedData), "crowdsec", bt)
	if err != nil {
		t.Fatalf("LoadFeed error: %v", err)
	}
	if n != 4 {
		t.Errorf("expected 4 valid entries loaded, got %d", n)
	}

	if !bt.InFeed(net.ParseIP("185.220.101.5"), "crowdsec") {
		t.Errorf("expected 185.220.101.5 in crowdsec")
	}
	if !bt.InFeed(net.ParseIP("198.51.100.42"), "crowdsec") {
		t.Errorf("expected 198.51.100.42 in crowdsec")
	}
	if !bt.InFeed(net.ParseIP("2001:db8:1:abc::1"), "crowdsec") {
		t.Errorf("expected IPv6 in crowdsec")
	}
}

func TestBARTTable_ConcurrentReadsAndAtomicUpdate(t *testing.T) {
	bt := NewBARTTable()
	_ = bt.InsertCIDR("10.0.0.0/8", "internal", "")

	var wg sync.WaitGroup
	ip := net.ParseIP("10.1.2.3")

	// Concurrent readers
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				_ = bt.Contains(ip)
				_ = bt.InFeed(ip, "internal")
			}
		}()
	}

	// Concurrent updater
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_ = bt.InsertCIDR(fmt.Sprintf("192.168.%d.0/24", i), "dynamic", "")
		}
	}()

	wg.Wait()
}

func BenchmarkBARTLookup(b *testing.B) {
	bt := NewBARTTable()
	// Pre-populate table with 10,000 subnets
	for i := 0; i < 100; i++ {
		for j := 0; j < 100; j++ {
			_ = bt.InsertCIDR(fmt.Sprintf("%d.%d.0.0/16", i, j), "bench_feed", "")
		}
	}

	targetIP := net.ParseIP("50.50.12.34")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !bt.Contains(targetIP) {
			b.Fatal("lookup failed")
		}
	}
}
