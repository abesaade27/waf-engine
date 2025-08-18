package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxJSONSize limits the maximum allowed JSON body size (e.g., 1MB)
const MaxJSONSize = 1 << 20 // 1 MB

// NormalizeHeaders converts header keys to lowercase, trims values, joins multiple values by comma
func NormalizeHeaders(headers map[string][]string) map[string]string {
	fmt.Println("🔹 [DEBUG] NormalizeHeaders called")
	normalized := make(map[string]string, len(headers))
	for key, values := range headers {
		lowerKey := strings.ToLower(key)
		fmt.Printf("   ↪ Normalizing header: %s -> %s\n", key, lowerKey)

		for i := range values {
			values[i] = strings.TrimSpace(values[i])
		}
		normalized[lowerKey] = strings.Join(values, ",")
		fmt.Printf("   ✔ Result: %s=%s\n", lowerKey, normalized[lowerKey])
	}
	fmt.Println("✅ [DEBUG] NormalizeHeaders finished")
	return normalized
}

// PreprocessJSONReader reads from io.Reader (like http.Request.Body), parses JSON stream, normalizes headers, and extracts body fields
func PreprocessJSONReader(r io.Reader) (map[string]string, map[string]interface{}, error) {
	fmt.Println("🔹 [DEBUG] PreprocessJSONReader called")

	// Limit the reader to MaxJSONSize bytes to avoid huge payloads
	limitedReader := io.LimitReader(r, MaxJSONSize)

	// Use json.Decoder for streaming parsing
	decoder := json.NewDecoder(limitedReader)

	var data map[string]interface{}
	if err := decoder.Decode(&data); err != nil {
		fmt.Printf("❌ [DEBUG] JSON decode failed: %v\n", err)
		return nil, nil, err
	}
	fmt.Println("✅ [DEBUG] JSON decoded successfully")

	headersRaw, ok := data["headers"]
	if !ok {
		fmt.Println("❌ [DEBUG] No 'headers' field found in JSON")
		return nil, nil, errors.New("no headers found")
	}

	headersInterface, ok := headersRaw.(map[string]interface{})
	if !ok {
		fmt.Println("❌ [DEBUG] Headers format incorrect (not map[string]interface{})")
		return nil, nil, errors.New("headers format incorrect")
	}

	headersMap := make(map[string][]string, len(headersInterface))
	for k, v := range headersInterface {
		arr, ok := v.([]interface{})
		if !ok {
			fmt.Printf("⚠️ [DEBUG] Skipping header %s: not array\n", k)
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
		fmt.Printf("   ✔ Parsed header %s: %v\n", k, strSlice)
	}

	normalizedHeaders := NormalizeHeaders(headersMap)

	// Extract body fields as generic map if present
	bodyRaw, _ := data["body"].(map[string]interface{})
	fmt.Printf("📦 [DEBUG] Extracted body: %v\n", bodyRaw)

	fmt.Println("✅ [DEBUG] PreprocessJSONReader finished")
	return normalizedHeaders, bodyRaw, nil
}
