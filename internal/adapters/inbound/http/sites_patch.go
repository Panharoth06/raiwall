package api

import (
	"encoding/json"
)

// applySitePatch overlays the fields present in an update request onto the
// stored site. Fields that are omitted keep their stored value, while fields
// that are present (including empty strings, empty arrays, and null) replace
// it. This keeps partial updates from silently dropping routing or TLS
// metadata.
func applySitePatch(existing SiteDTO, patch SiteDTO, provided map[string]json.RawMessage) SiteDTO {
	out := existing
	has := func(key string) bool {
		_, ok := provided[key]
		return ok
	}

	if has("name") {
		out.Name = patch.Name
	}
	if has("description") {
		out.Description = patch.Description
	}
	if has("hostnames") {
		out.Hostnames = patch.Hostnames
	}
	if has("mode") {
		out.Mode = patch.Mode
	}
	if has("ports") {
		out.Ports = patch.Ports
	}
	if has("ssl_mode") {
		out.SSLMode = patch.SSLMode
	}
	if has("certificate_id") {
		out.CertificateID = patch.CertificateID
	}
	if has("routing_type") {
		out.RoutingType = patch.RoutingType
	}
	if has("document_root") {
		out.DocumentRoot = patch.DocumentRoot
	}
	if has("redirect_url") {
		out.RedirectURL = patch.RedirectURL
	}
	if has("redirect_status") {
		out.RedirectStatus = patch.RedirectStatus
	}
	if has("load_balancing") {
		out.LoadBalancing = patch.LoadBalancing
	}
	if has("upstreams") {
		out.Upstreams = patch.Upstreams
	}
	if has("proxy_settings") {
		out.ProxySettings = patch.ProxySettings
	}
	if has("block_status_code") {
		out.BlockStatusCode = patch.BlockStatusCode
	}
	if has("block_response_body") {
		out.BlockResponseBody = patch.BlockResponseBody
	}
	if has("offline_status_code") {
		out.OfflineStatusCode = patch.OfflineStatusCode
	}
	if has("offline_response_body") {
		out.OfflineResponseBody = patch.OfflineResponseBody
	}
	if has("custom_headers") {
		out.CustomHeaders = patch.CustomHeaders
	}
	if has("auth_enabled") {
		out.AuthEnabled = patch.AuthEnabled
	}
	if has("auth_bypass_paths") {
		out.AuthBypassPaths = patch.AuthBypassPaths
	}
	return out
}
