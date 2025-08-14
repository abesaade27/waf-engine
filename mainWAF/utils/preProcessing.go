package utils

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"strings"
)

// MaxJSONSize limits the maximum allowed JSON body size (e.g., 1MB)
const MaxJSONSize = 1 << 20 // 1 MB

// NormalizeHeaders converts header keys to lowercase, trims values, joins multiple values by comma
func NormalizeHeaders(headers map[string][]string) map[string]string {
	normalized := make(map[string]string, len(headers))
	for key, values := range headers {
		lowerKey := strings.ToLower(key)
		for i := range values {
			values[i] = strings.TrimSpace(values[i])
		}
		normalized[lowerKey] = strings.Join(values, ",")
	}
	return normalized
}

// PreprocessJSONReader reads from io.Reader (like http.Request.Body), parses JSON stream, normalizes headers, and extracts body fields
func PreprocessJSONReader(r io.Reader) (map[string]string, map[string]interface{}, error) {
	// Limit the reader to MaxJSONSize bytes to avoid huge payloads
	limitedReader := io.LimitReader(r, MaxJSONSize)

	// Use json.Decoder for streaming parsing
	decoder := json.NewDecoder(limitedReader)

	var data map[string]interface{}
	if err := decoder.Decode(&data); err != nil {
		return nil, nil, err
	}

	headersRaw, ok := data["headers"]
	if !ok {
		return nil, nil, errors.New("no headers found")
	}

	headersInterface, ok := headersRaw.(map[string]interface{})
	if !ok {
		return nil, nil, errors.New("headers format incorrect")
	}

	headersMap := make(map[string][]string, len(headersInterface))
	for k, v := range headersInterface {
		arr, ok := v.([]interface{})
		if !ok {
			continue
		}
		// Preallocate slice with capacity for efficiency
		strSlice := make([]string, 0, len(arr))
		for _, val := range arr {
			if strVal, ok := val.(string); ok {
				strSlice = append(strSlice, strVal)
			}
		}
		headersMap[k] = strSlice
	}

	normalizedHeaders := NormalizeHeaders(headersMap)

	// Extract body fields as generic map if present
	bodyRaw, _ := data["body"].(map[string]interface{})
	log.Printf("Normalized Headers: %+v", normalizedHeaders)

	return normalizedHeaders, bodyRaw, nil
}
