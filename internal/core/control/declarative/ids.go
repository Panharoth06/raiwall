package declarative

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// IDPrefix marks records owned by the declarative configuration file. Records
// with this prefix cannot be edited or deleted through the control-plane API;
// operators change the YAML file and redeploy instead.
const IDPrefix = "cfg:"

// Resource kinds used in deterministic identifiers.
const (
	KindApplication      = "app"
	KindCertificate      = "certificate"
	KindForwarding       = "forwarding"
	KindException        = "exception"
	KindACL              = "acl"
	KindIPGroup          = "ip_group"
	KindRatePolicy       = "rate_policy"
	KindBotPolicy        = "bot_policy"
	KindIdentityProvider = "identity_provider"
	KindTemplate         = "template"
)

// IsManaged reports whether id belongs to the declarative configuration file.
func IsManaged(id string) bool {
	return strings.HasPrefix(id, IDPrefix)
}

// namedID builds the stable identifier for a named resource.
func namedID(kind, name string) string {
	return IDPrefix + kind + ":" + name
}

// hashedID builds a stable identifier for resources whose natural key is not a
// valid slug (forwarding prefixes, unnamed exceptions, and so on).
func hashedID(kind string, parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return IDPrefix + kind + ":" + hex.EncodeToString(h.Sum(nil))[:16]
}
