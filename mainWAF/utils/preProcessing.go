/*
WAF Utility Functions

This package provides helper utilities for preprocessing HTTP requests, normalizing headers,
and handling JSON bodies for the WAF. These utilities simplify inspection and rule matching.

Key Components:

1. MaxJSONSize
  - Limits the maximum allowed JSON body size to prevent huge payloads from overwhelming the WAF.
  - Currently set to 1 MB (1 << 20 bytes).

2. NormalizeHeaders(headers map[string][]string) map[string]string
  - Converts all header keys to lowercase for consistent rule matching.
  - Trims whitespace from each header value.
  - Joins multiple values of the same header with a comma.
  - Returns a normalized map[string]string ready for inspection.

3. PreprocessJSONReader(r io.Reader) (map[string]string, map[string]interface{}, error)
  - Reads from an io.Reader (like http.Request.Body) with a size limit of MaxJSONSize.
  - Parses JSON using json.Decoder (streaming-safe).
  - Normalizes headers found under the "headers" key in the JSON.
  - Extracts the "body" object as a generic map[string]interface{}.
  - Returns normalized headers, extracted body, and any parsing error.
  - Logs normalized headers for debugging.

Usage:
  - Call NormalizeHeaders(...) when inspecting request headers to ensure uniform key/value formatting.
  - Call PreprocessJSONReader(...) when reading JSON payloads to safely parse, normalize, and extract headers/body
    for rule inspection.
  - Supports safe inspection of potentially large JSON bodies without reading unlimited data into memory.
*/
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
