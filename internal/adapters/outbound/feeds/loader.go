package feeds

import (
	"io"

	"github.com/Panharoth06/raiwall/internal/core/acl"
)

// LoadFeed reads line-delimited IP or CIDR entries from an io.Reader and inserts them into table.
func LoadFeed(r io.Reader, feedName string, table *acl.BARTTable) (int, error) {
	return acl.LoadFeed(r, feedName, table)
}

// LoadFeedFile opens a file from filePath and loads it into table.
func LoadFeedFile(filePath string, feedName string, table *acl.BARTTable) (int, error) {
	return acl.LoadFeedFile(filePath, feedName, table)
}

// BuildTableFromFeeds creates a fresh BARTTable populated with entries from a map of feedName -> io.Reader.
func BuildTableFromFeeds(feeds map[string]io.Reader) (*acl.BARTTable, error) {
	return acl.BuildTableFromFeeds(feeds)
}
