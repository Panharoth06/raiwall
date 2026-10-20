package acl

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/gaissmai/bart"
)

// LoadFeed reads line-delimited IP or CIDR entries from an io.Reader and inserts them into table under feedName.
// Strips comments (#, //, ;) and whitespace.
func LoadFeed(r io.Reader, feedName string, table *BARTTable) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("reader cannot be nil")
	}
	if table == nil {
		return 0, fmt.Errorf("table cannot be nil")
	}

	scanner := bufio.NewScanner(r)
	prefixes := make([]netip.Prefix, 0, 1024)

	for scanner.Scan() {
		line := cleanFeedLine(scanner.Text())
		if line == "" {
			continue
		}

		pfx, err := ParsePrefix(line)
		if err != nil {
			// Skip malformed line rather than failing whole feed
			continue
		}
		prefixes = append(prefixes, pfx)
	}

	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("scan feed %q: %w", feedName, err)
	}

	table.BatchInsert(prefixes, feedName, "")
	return len(prefixes), nil
}

// LoadFeedFile opens a file from filePath and loads it into table.
func LoadFeedFile(filePath string, feedName string, table *BARTTable) (int, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("open feed file %q: %w", filePath, err)
	}
	defer f.Close()

	return LoadFeed(f, feedName, table)
}

// BuildTableFromFeeds creates a fresh BARTTable populated with entries from a map of feedName -> io.Reader.
func BuildTableFromFeeds(feeds map[string]io.Reader) (*BARTTable, error) {
	bt := NewBARTTable()
	rawTable := new(bart.Table[ThreatEntry])

	for feedName, r := range feeds {
		if r == nil {
			continue
		}
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := cleanFeedLine(scanner.Text())
			if line == "" {
				continue
			}
			pfx, err := ParsePrefix(line)
			if err != nil {
				continue
			}

			rawTable.Modify(pfx, func(val ThreatEntry, exists bool) (ThreatEntry, bool) {
				if !exists {
					return ThreatEntry{Feeds: []string{feedName}}, false
				}
				if !val.HasFeed(feedName) {
					val.Feeds = append(val.Feeds, feedName)
				}
				return val, false
			})
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("build feed %q: %w", feedName, err)
		}
	}

	bt.UpdateTable(rawTable)
	return bt, nil
}

// cleanFeedLine strips comments and extra whitespace.
func cleanFeedLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Strip inline comments
	if idx := strings.IndexByte(line, '#'); idx != -1 {
		line = line[:idx]
	}
	if idx := strings.Index(line, "//"); idx != -1 {
		line = line[:idx]
	}
	if idx := strings.IndexByte(line, ';'); idx != -1 {
		line = line[:idx]
	}

	// Line might contain trailing fields (e.g. "192.168.1.1 name metadata")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
