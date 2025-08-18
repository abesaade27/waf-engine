package utils

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

// ----------------------------
// FlattenJSON: converts nested JSON into a flat string for regex matching
// ----------------------------
// ----------------------------
// FlattenJSON: converts nested JSON into a flat string for regex matching
// ----------------------------
func FlattenJSON(data any) string {
	switch v := data.(type) {
	case map[string]any:
		parts := []string{}
		fmt.Println("FlattenJSON: entering map =>", v)
		for key, val := range v {
			flattened := FlattenJSON(val)
			kv := key + "=" + flattened
			fmt.Println("FlattenJSON: map entry =>", kv)
			parts = append(parts, kv)
		}
		joined := strings.Join(parts, "&")
		fmt.Println("FlattenJSON: map joined =>", joined)
		return joined

	case []any:
		parts := []string{}
		fmt.Println("FlattenJSON: entering slice =>", v)
		for _, val := range v {
			flattened := FlattenJSON(val)
			fmt.Println("FlattenJSON: slice element =>", flattened)
			parts = append(parts, flattened)
		}
		joined := strings.Join(parts, ",")
		fmt.Println("FlattenJSON: slice joined =>", joined)
		return joined

	case string:
		fmt.Println("FlattenJSON: string =>", v)
		return v

	default:
		fmt.Println("FlattenJSON: unknown type =>", v)
		return ""
	}
}

// ----------------------------
// Helper: lowerKeys converts all map keys to lowercase
// ----------------------------
func lowerKeys(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[strings.ToLower(k)] = v
	}
	return out
}

// ----------------------------
// NormalizeHTTP: fully normalizes HTTP requests for WAF inspection
// ----------------------------
func NormalizeHTTP(r *http.Request) (method, path string, query map[string][]string, headers map[string]string, body map[string]any) {
	method = r.Method

	// Decode URL path
	path, _ = url.PathUnescape(r.URL.Path)

	// Decode query parameters
	query = make(map[string][]string)
	for k, vals := range r.URL.Query() {
		key, _ := url.QueryUnescape(k)
		for _, v := range vals {
			val, _ := url.QueryUnescape(v)
			query[key] = append(query[key], val)
		}
	}

	// Normalize headers
	headers = make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = v[0]
		}
	}

	// Initialize body map
	body = map[string]any{}

	if r.Body != nil {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			fmt.Println("❌ Error reading body:", err)
		}
		r.Body.Close()

		fmt.Println("=== Raw Body (as received) ===")
		fmt.Println(string(raw))

		// Reset body so it can still be parsed later
		r.Body = io.NopCloser(bytes.NewBuffer(raw))

		ct := strings.ToLower(r.Header.Get("Content-Type"))
		mediaType, params, _ := mime.ParseMediaType(ct)

		switch mediaType {
		case "application/json":
			_ = json.Unmarshal(raw, &body)

		case "application/x-www-form-urlencoded":
			values, _ := url.ParseQuery(string(raw))
			if len(values) > 0 {
				for k, vals := range values {
					body[k] = vals
				}
			} else {
				// 🚨 fallback: decode raw fully
				decoded, _ := url.QueryUnescape(string(raw))
				body["raw"] = decoded
			}

		case "multipart/form-data":
			boundary := params["boundary"]
			if boundary != "" {
				mr := multipart.NewReader(bytes.NewReader(raw), boundary)
				form, _ := mr.ReadForm(1 << 20) // 1MB max memory
				for k, vals := range form.Value {
					body[k] = vals
				}
			}

		default:
			body["raw"] = string(raw)
		}
	}

	// Print everything after normalization
	fmt.Println("=== Normalized Request ===")
	fmt.Println("Method:", method)
	fmt.Println("Path:", path)
	fmt.Println("Query:", query)
	fmt.Println("Headers:", headers)
	fmt.Println("Body:", body)

	return
}

// ----------------------------
// Ingest struct for JSON ingestion
// ----------------------------
type Ingest struct {
	Headers map[string]string   `json:"headers"`
	Body    map[string]any      `json:"body"`
	Query   map[string][]string `json:"query"`
	Path    string              `json:"path"`
	Method  string              `json:"method"`
}

// ----------------------------
// NormalizeIngest: normalizes ingested JSON events for WAF inspection
// ----------------------------
func NormalizeIngest(i *Ingest) (method, path string, query map[string][]string, headers map[string]string, body map[string]any, flatBody string) {
	// Default method to POST if not provided
	method = i.Method
	if method == "" {
		method = "POST"
	}

	// Lowercase headers
	headers = lowerKeys(i.Headers)

	// Copy path and query (with URL decoding)
	path = i.Path
	query = make(map[string][]string, len(i.Query))
	for k, vals := range i.Query {
		key, _ := url.QueryUnescape(k)
		for _, v := range vals {
			val, _ := url.QueryUnescape(v)
			query[key] = append(query[key], val)
		}
	}

	// Copy body map
	body = i.Body

	// --- FIX: detect malformed ARGS (like single "a") and treat as raw ---
	if len(body) == 1 {
		for k, v := range body {
			// If key has no '=' and value is empty slice, treat as raw
			if vSlice, ok := v.([]any); ok && len(vSlice) == 0 {
				body = map[string]any{"raw": k}
				break
			}
		}
	}

	// Flatten body for regex matching
	flatBody = FlattenJSON(body)

	// Debug prints
	fmt.Println("=== Normalized Ingest ===")
	fmt.Println("Method:", method)
	fmt.Println("Path:", path)
	fmt.Println("Query:", query)
	fmt.Println("Headers:", headers)
	fmt.Println("Body (map):", body)
	fmt.Println("Flat Body (string):", flatBody)

	return
}
