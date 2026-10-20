package normalizer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
)

// extractJSONParameters traverses a JSON payload and flattens objects/arrays into key-value parameters.
func extractJSONParameters(body []byte) []Parameter {
	var params []Parameter
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
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
			params = append(params, Parameter{
				Name:     fieldName + ".filename",
				Value:    fileName,
				Location: LocationMultipart,
			})

			lr := io.LimitReader(part, MaxMultipartFileSize+1)
			data, readErr := io.ReadAll(lr)
			if readErr == nil && len(data) <= MaxMultipartFileSize {
				if isLikelyText(data) {
					params = append(params, Parameter{
						Name:     fieldName + ".content",
						Value:    string(data),
						Location: LocationMultipart,
					})
				}
			}
		} else {
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
