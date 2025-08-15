package utils

import (
	"fmt"
)

// flattenJSON recursively flattens nested JSON objects and arrays into a flat map.
// Keys are dot/bracket notation so that nested JSON fields can be easily scanned
// by your WAF rules.
func FlattenJSON(data map[string]interface{}, prefix string, out map[string]string) {
	for key, value := range data {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := value.(type) {
		case map[string]interface{}:
			// Recursively flatten nested objects
			FlattenJSON(v, fullKey, out)

		case []interface{}:
			// Handle arrays
			for i, elem := range v {
				if m, ok := elem.(map[string]interface{}); ok {
					FlattenJSON(m, fmt.Sprintf("%s[%d]", fullKey, i), out)
				} else {
					out[fmt.Sprintf("%s[%d]", fullKey, i)] = fmt.Sprintf("%v", elem)
				}
			}

		default:
			// Base case: primitive value
			out[fullKey] = fmt.Sprintf("%v", value)
		}
	}
}
