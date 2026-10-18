package normalizer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
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
		params = append(params, Parameter{
			Name:     "query",
			Value:    query,
			Location: LocationQuery,
		})

		if parsedQuery, err := url.ParseQuery(query); err == nil {
			for key, values := range parsedQuery {
				for _, val := range values {
					params = append(params, Parameter{
						Name:     key,
						Value:    val,
						Location: LocationQuery,
					})
				}
			}
		}
	}

	// 3. Headers (Cookies, Authorization, custom X- headers, User-Agent, Referer)
	if headers != nil {
		for key, values := range headers {
			lowerKey := strings.ToLower(key)
			if lowerKey == "cookie" {
				for _, val := range values {
					// Also split individual cookies
					cookieParts := strings.Split(val, ";")
					for _, cp := range cookieParts {
						cp = strings.TrimSpace(cp)
						if eqIdx := strings.IndexByte(cp, '='); eqIdx != -1 {
							params = append(params, Parameter{
								Name:     cp[:eqIdx],
								Value:    cp[eqIdx+1:],
								Location: LocationHeader,
							})
						} else if cp != "" {
							params = append(params, Parameter{
								Name:     "cookie",
								Value:    cp,
								Location: LocationHeader,
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
				// Fallback to raw body parameter
				params = append(params, Parameter{
					Name:     "body",
					Value:    string(body),
					Location: LocationBody,
				})
			}

		case mediaType == "application/x-www-form-urlencoded" || mediaType == "":
			// Form-urlencoded or unspecified content-type
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
			// Plain text, xml, etc.
			params = append(params, Parameter{
				Name:     "body",
				Value:    string(body),
				Location: LocationBody,
			})
		}
	}

	return params
}

// extractJSONParameters traverses a JSON payload and flattens objects/arrays into key-value parameters.
func extractJSONParameters(body []byte) []Parameter {
	var params []Parameter
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		// If malformed JSON, pass raw body string
		return []Parameter{{
			Name:     "body",
			Value:    string(body),
			Location: LocationJSON,
		}}
	}

	traverseJSON("", raw, &params)
	return params
}

func traverseJSON(prefix string, val any, params *[]Parameter) {
	switch v := val.(type) {
	case map[string]any:
		for k, child := range v {
			// Also inspect object keys as potential injection vectors
			*params = append(*params, Parameter{
				Name:     "json_key",
				Value:    k,
				Location: LocationJSON,
			})
			fullKey := k
			if prefix != "" {
				fullKey = prefix + "." + k
			}
			traverseJSON(fullKey, child, params)
		}
	case []any:
		for i, child := range v {
			fullKey := fmt.Sprintf("%s[%d]", prefix, i)
			traverseJSON(fullKey, child, params)
		}
	case string:
		key := prefix
		if key == "" {
			key = "value"
		}
		*params = append(*params, Parameter{
			Name:     key,
			Value:    v,
			Location: LocationJSON,
		})
	case float64:
		// Optional: numbers are generally benign, but convert to string representation
		key := prefix
		if key == "" {
			key = "value"
		}
		*params = append(*params, Parameter{
			Name:     key,
			Value:    fmt.Sprintf("%v", v),
			Location: LocationJSON,
		})
	case bool:
		key := prefix
		if key == "" {
			key = "value"
		}
		*params = append(*params, Parameter{
			Name:     key,
			Value:    fmt.Sprintf("%t", v),
			Location: LocationJSON,
		})
	}
}

// extractMultipartParameters parses multipart/form-data. Text fields and metadata are inspected;
// file upload contents > 1 MB are skipped from in-memory inspection.
func extractMultipartParameters(body []byte, boundary string) []Parameter {
	var params []Parameter
	reader := multipart.NewReader(bytes.NewReader(body), boundary)

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		fieldName := part.FormName()
		fileName := part.FileName()

		if fileName != "" {
			// 1. Inspect filename
			params = append(params, Parameter{
				Name:     fieldName + ".filename",
				Value:    fileName,
				Location: LocationMultipart,
			})

			// 2. Selective inspection: if file is text/small, inspect header metadata only,
			// or skip body if > MaxMultipartFileSize.
			lr := io.LimitReader(part, MaxMultipartFileSize+1)
			data, readErr := io.ReadAll(lr)
			if readErr == nil && len(data) <= MaxMultipartFileSize {
				// If text or json file, inspect contents
				if isLikelyText(data) {
					params = append(params, Parameter{
						Name:     fieldName + ".content",
						Value:    string(data),
						Location: LocationMultipart,
					})
				}
			}
		} else {
			// Normal form text field
			val, readErr := io.ReadAll(io.LimitReader(part, MaxMultipartFileSize))
			if readErr == nil {
				params = append(params, Parameter{
					Name:     fieldName,
					Value:    string(val),
					Location: LocationMultipart,
				})
			}
		}
		_ = part.Close()
	}

	return params
}

// isLikelyText checks if byte buffer contains human-readable UTF-8 text without excessive nulls.
func isLikelyText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	checkLen := len(data)
	if checkLen > 512 {
		checkLen = 512
	}
	nullCount := 0
	for i := 0; i < checkLen; i++ {
		if data[i] == 0 {
			nullCount++
		}
	}
	return float64(nullCount)/float64(checkLen) < 0.05
}
