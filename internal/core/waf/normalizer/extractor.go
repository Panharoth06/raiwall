package normalizer

import (
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// Location designates where a request parameter originated.
type Location string

const (
	LocationPath      Location = "Path"
	LocationQuery     Location = "Query"
	LocationHeader    Location = "Header"
	LocationCookie    Location = "Cookie"
	LocationBody      Location = "Body"
	LocationJSON      Location = "JSON"
	LocationMultipart Location = "Multipart"
)

// Parameter models an extracted request parameter candidate for threat analysis.
type Parameter struct {
	Name     string   `json:"name"`
	Value    string   `json:"value"`
	Location Location `json:"location"`
}

// MaxMultipartFileSize defines the 1 MB cap where file upload streams pass directly to upstream.
const MaxMultipartFileSize = 1024 * 1024

// ExtractParameters parses all parameters across Path, Query, Headers, and Body.
func ExtractParameters(path string, query string, headers http.Header, body []byte) []Parameter {
	var params []Parameter

	// 1. Path
	if path != "" {
		params = append(params, Parameter{
			Name:     "path",
			Value:    path,
			Location: LocationPath,
		})
	}

	// 2. Query
	if query != "" {
		if parsedQuery, err := url.ParseQuery(query); err == nil && len(parsedQuery) > 0 {
			for key, values := range parsedQuery {
				if key != "" {
					params = append(params, Parameter{
						Name:     "query_key",
						Value:    key,
						Location: LocationQuery,
					})
				}
				for _, val := range values {
					params = append(params, Parameter{
						Name:     key,
						Value:    val,
						Location: LocationQuery,
					})
				}
			}
		} else {
			params = append(params, Parameter{
				Name:     "query",
				Value:    query,
				Location: LocationQuery,
			})
		}
	}

	// 3. Headers (Cookies, Authorization, custom X- headers, User-Agent, Referer)
	if headers != nil {
		for key, values := range headers {
			lowerKey := strings.ToLower(key)
			if lowerKey == "cookie" {
				for _, val := range values {
					cookieParts := strings.Split(val, ";")
					for _, cp := range cookieParts {
						cp = strings.TrimSpace(cp)
						if eqIdx := strings.IndexByte(cp, '='); eqIdx != -1 {
							params = append(params, Parameter{
								Name:     cp[:eqIdx],
								Value:    cp[eqIdx+1:],
								Location: LocationCookie,
							})
						} else if cp != "" {
							params = append(params, Parameter{
								Name:     "cookie",
								Value:    cp,
								Location: LocationCookie,
							})
						}
					}
				}
			} else if strings.HasPrefix(lowerKey, "x-") ||
				lowerKey == "authorization" ||
				lowerKey == "user-agent" ||
				lowerKey == "referer" {
				for _, val := range values {
					params = append(params, Parameter{
						Name:     key,
						Value:    val,
						Location: LocationHeader,
					})
				}
			}
		}
	}

	// 4. Body
	if len(body) > 0 {
		contentType := ""
		if headers != nil {
			contentType = headers.Get("Content-Type")
		}

		mediaType, paramsMap, _ := mime.ParseMediaType(contentType)

		switch {
		case strings.Contains(mediaType, "json"):
			params = append(params, extractJSONParameters(body)...)

		case mediaType == "multipart/form-data":
			boundary, ok := paramsMap["boundary"]
			if ok && boundary != "" {
				params = append(params, extractMultipartParameters(body, boundary)...)
			} else {
				params = append(params, Parameter{
					Name:     "body",
					Value:    string(body),
					Location: LocationBody,
				})
			}

		case mediaType == "application/x-www-form-urlencoded" || mediaType == "":
			if parsedForm, err := url.ParseQuery(string(body)); err == nil && len(parsedForm) > 0 {
				for key, values := range parsedForm {
					for _, val := range values {
						params = append(params, Parameter{
							Name:     key,
							Value:    val,
							Location: LocationBody,
						})
					}
				}
			} else {
				params = append(params, Parameter{
					Name:     "body",
					Value:    string(body),
					Location: LocationBody,
				})
			}

		default:
			params = append(params, Parameter{
				Name:     "body",
				Value:    string(body),
				Location: LocationBody,
			})
		}
	}

	return params
}
