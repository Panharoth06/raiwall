package auth

import (
	"net/http"
	"strings"
)

// StripAuthHeaders deletes any client-supplied X-Auth-* headers to prevent
// identity spoofing.
func StripAuthHeaders(headers http.Header) {
	if headers == nil {
		return
	}
	headers.Del(HeaderAuthSubject)
	headers.Del(HeaderAuthEmail)
	headers.Del(HeaderAuthName)
	headers.Del(HeaderAuthRoles)
}

// InjectIdentityHeaders strips untrusted X-Auth-* headers and injects
// verified claims.
func InjectIdentityHeaders(headers http.Header, identity *UserIdentity) {
	if headers == nil || identity == nil {
		return
	}
	StripAuthHeaders(headers)
	headers.Set(HeaderAuthSubject, identity.Subject)
	if identity.Email != "" {
		headers.Set(HeaderAuthEmail, identity.Email)
	}
	if identity.Name != "" {
		headers.Set(HeaderAuthName, identity.Name)
	}
	if len(identity.Roles) > 0 {
		headers.Set(HeaderAuthRoles, strings.Join(identity.Roles, ","))
	}
}
