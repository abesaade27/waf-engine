package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/text/unicode/norm"
)

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
// RecursiveUnescape decodes repeatedly until stable (max 5 iterations to prevent loops)
// ----------------------------
func RecursiveUnescape(input string) string {
	prev := input
	for i := 0; i < 5; i++ {
		decoded, err := url.QueryUnescape(prev)
		if err != nil || decoded == prev {
			break
		}
		prev = decoded
	}
	return prev
}

// ----------------------------
// NormalizeUnicode canonicalizes Unicode into NFKC form
// ----------------------------
func NormalizeUnicode(input string) string {
	return norm.NFKC.String(input)
}

// ----------------------------
// ReplaceHomoglyphs maps common full-width ASCII characters to normal ASCII
// ----------------------------
func ReplaceHomoglyphs(input string) string {
	out := []rune{}
	for _, r := range input {
		// full-width ASCII range U+FF01–U+FF5E
		if r >= 0xFF01 && r <= 0xFF5E {
			r = rune(r - 0xFEE0)
		}
		out = append(out, r)
	}
	return string(out)
}

// ----------------------------
// Canonicalize applies full normalization pipeline
// ----------------------------
func Canonicalize(input string) string {
	s := RecursiveUnescape(input)
	s = NormalizeUnicode(s)
	s = ReplaceHomoglyphs(s)
	return s
}

// ----------------------------
// NormalizeHTTP: fully normalizes HTTP requests for WAF inspection
// ----------------------------
// ----------------------------
// NormalizeHTTP: fully normalizes HTTP requests for WAF inspection
// ----------------------------
func NormalizeHTTP(r *http.Request) (method string, headers map[string]string, body map[string]any) {
	method = r.Method

	// ✅ Normalize headers (raw + JSON detection)
	headers = make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = Canonicalize(v[0])
		}
	}

	// ✅ Initialize body map
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
		mediaType, _, _ := mime.ParseMediaType(ct)

		if strings.Contains(mediaType, "json") {
			// ✅ Handle JSON body
			body = NormalizeOrSalvageJSON(raw)
		} else {
			// ✅ Fallback: treat as raw text body
			body["raw"] = Canonicalize(string(raw))
		}
	}

	// ✅ Debug print
	fmt.Println("=== Normalized Request ===")
	fmt.Println("Method:", method)
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
	RawBody []byte
}

// ----------------------------
// NormalizeIngest: normalizes ingested JSON events for WAF inspection
// ----------------------------
func NormalizeIngest(i *Ingest) (
	method string,
	path string,
	query map[string][]string,
	headers map[string]string,
	body map[string]any,
	flatBody string,
) {
	// Default method to POST if not provided
	method = i.Method
	if method == "" {
		method = "POST"
	}

	// Lowercase + canonicalize headers
	headers = lowerKeys(i.Headers)
	for k, v := range headers {
		headers[k] = Canonicalize(v)
	}

	// Canonicalize path
	path = Canonicalize(i.Path)

	// Copy + canonicalize query
	query = make(map[string][]string, len(i.Query))
	for k, vals := range i.Query {
		key := Canonicalize(RecursiveUnescape(k))
		for _, v := range vals {
			val := Canonicalize(RecursiveUnescape(v))
			query[key] = append(query[key], val)
		}
	}

	// Copy body map
	body = map[string]any{}
	for k, v := range i.Body {
		// For string slices
		if arr, ok := v.([]string); ok {
			cVals := []string{}
			for _, s := range arr {
				cVals = append(cVals, Canonicalize(s))
			}
			body[Canonicalize(k)] = cVals
			continue
		}
		// For direct strings
		if s, ok := v.(string); ok {
			body[Canonicalize(k)] = Canonicalize(s)
			continue
		}
		// Fallback: keep as is
		body[Canonicalize(k)] = v
	}

	// --- FIX: detect malformed ARGS (like single "a") and treat as raw ---
	if len(body) == 1 {
		for k, v := range body {
			if vSlice, ok := v.([]any); ok && len(vSlice) == 0 {
				body = map[string]any{"raw": Canonicalize(k)}
				break
			}
		}
	}

	// --- NEW: salvage fallback if JSON is broken ---
	if ct, ok := headers["content-type"]; ok && strings.Contains(ct, "json") {
		if len(i.RawBody) > 0 {
			body = NormalizeOrSalvageJSON(i.RawBody)
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

// ----------------------------
// FlattenJSON: converts nested JSON into a flat string for regex matching
// ----------------------------
func FlattenJSON(data any) string {
	switch v := data.(type) {
	case map[string]any:
		parts := []string{}
		for key, val := range v {
			flattened := FlattenJSON(val)
			kv := Canonicalize(key) + "=" + flattened
			parts = append(parts, kv)
		}
		return strings.Join(parts, "&")

	case []any:
		parts := []string{}
		for _, val := range v {
			flattened := FlattenJSON(val)
			parts = append(parts, flattened)
		}
		return strings.Join(parts, ",")

	case string:
		return Canonicalize(v)

	// ✅ FIX: handle numbers
	case float64, int, int64:
		return fmt.Sprintf("%v", v)

	// ✅ FIX: handle booleans
	case bool:
		return fmt.Sprintf("%t", v)

	// ✅ FIX: handle null
	case nil:
		return "null"

	default:
		return fmt.Sprintf("%v", v) // fallback generic
	}
}

// --- Helper: Normalize or salvage JSON body ---
func NormalizeOrSalvageJSON(raw []byte) map[string]any {
	result := map[string]any{}

	tryDecode := func(data []byte) (map[string]any, bool) {
		tmp := map[string]any{}
		if err := json.Unmarshal(data, &tmp); err == nil {
			return tmp, true
		}
		return nil, false
	}

	// ✅ 1. First attempt
	if tmp, ok := tryDecode(raw); ok {
		return canonicalizeMap(tmp)
	}

	// ✅ 2. Try unescaping + re-decode
	unescaped := RecursiveUnescape(string(raw))
	if tmp, ok := tryDecode([]byte(unescaped)); ok {
		return canonicalizeMap(tmp)
	}

	// ✅ 3. Fallback salvage (raw + key:value split)
	canonical := Canonicalize(unescaped)
	result["raw"] = canonical

	stripped := strings.Trim(canonical, "{} ")
	for _, p := range strings.Split(stripped, ",") {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			k := Canonicalize(strings.TrimSpace(kv[0]))
			v := Canonicalize(strings.TrimSpace(kv[1]))
			if k != "" && v != "" {
				result[k] = v
			}
		}
	}
	return result
}

// ✅ Helper: canonicalize map keys + preserve structure
func canonicalizeMap(in map[string]any) map[string]any {
	out := make(map[string]any)
	for k, v := range in {
		out[Canonicalize(k)] = v // keep structure intact
	}
	return out
}
