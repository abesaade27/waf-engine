package utils

import (
	"encoding/json"
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
func FlattenJSON(data any) string {
	switch v := data.(type) {
	case map[string]any:
		parts := []string{}
		for key, val := range v {
			parts = append(parts, key+"="+FlattenJSON(val))
		}
		return strings.Join(parts, "&")
	case []any:
		parts := []string{}
		for _, val := range v {
			parts = append(parts, FlattenJSON(val))
		}
		return strings.Join(parts, ",")
	case string:
		return v
	default:
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
		defer r.Body.Close()
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		mediaType, params, _ := mime.ParseMediaType(ct)
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit

		switch mediaType {
		case "application/json":
			_ = json.Unmarshal(raw, &body)

		case "application/x-www-form-urlencoded":
			values, _ := url.ParseQuery(string(raw))
			for k, vals := range values {
				body[k] = vals
			}

		case "multipart/form-data":
			boundary := params["boundary"]
			if boundary != "" {
				mr := multipart.NewReader(strings.NewReader(string(raw)), boundary)
				form, _ := mr.ReadForm(1 << 20) // 1MB max memory
				for k, vals := range form.Value {
					body[k] = vals
				}
			}

		default:
			// fallback: store raw body as string
			body["raw"] = string(raw)
		}
	}

	return
}

// ----------------------------
// Ingest struct: represents a JSON payload already containing headers, body, query, and path
// ----------------------------
type Ingest struct {
	Headers map[string]string   `json:"headers"`
	Body    map[string]any      `json:"body"`
	Query   map[string][]string `json:"query"`
	Path    string              `json:"path"`
	Method  string              `json:"method"` // optional, default POST
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

	// Flatten body for regex matching
	flatBody = FlattenJSON(body)

	return
}
