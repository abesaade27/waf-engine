package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"waf-engine/mainWAF/rules"
	"waf-engine/mainWAF/utils"
)

type Request struct {
	Method  string
	Path    string
	Query   map[string][]string
	Headers map[string]string
	Body    map[string]any
}

type Transaction struct {
	InboundScore  int
	Matches       []string // keeps log messages of matched rules
	Score         int      // total score
	CriticalScore int      // critical rule score
	Block         bool
	Critical      int // should block request
}

// Decision struct for WAF response
type Decision struct {
	Block         bool
	Score         int
	Message       string
	MatchedRuleID string
}

// ==========================
// Evaluator + Constructor
// ==========================
type Evaluator struct {
	rules []rules.Rule
}

func NewEvaluator(rules []rules.Rule) *Evaluator {
	return &Evaluator{rules: rules}
}

// ==========================
// InspectPhases (CRS style with variable expansion)
// ==========================
func (e *Evaluator) InspectPhases(req *Request) Decision {
	dec := Decision{Block: false, Score: 0, Message: ""}
	firedRules := make(map[string]bool)

	for _, rule := range e.rules {
		if rule.Regex == "" {
			continue
		}

		varNames := strings.Split(rule.Variable, "|")
		for _, varName := range varNames {
			candidates := e.expandVariable(varName, req)
			for _, val := range candidates {
				if val == "" {
					continue
				}

				re, err := regexp.Compile(rule.Regex)
				if err != nil {
					continue
				}

				if re.MatchString(val) && !firedRules[rule.ID] {
					firedRules[rule.ID] = true
					dec.Score++
					if rule.Block {
						dec.Block = true
						dec.Message += fmt.Sprintf("🚫 Blocked by rule %s: %s in %s\n", rule.ID, rule.Name, varName)
					} else {
						dec.Message += fmt.Sprintf("⚠️ Detected by rule %s: %s in %s\n", rule.ID, rule.Name, varName)
					}
				}
			}
		}
	}

	return dec
}

// ==========================
// HTTPHandler (flatten and normalize correctly)
// ==========================
func HTTPHandler(eval *Evaluator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, _, _, _, _ := utils.NormalizeHTTP(r)
		variables := make(map[string]string)

		// Basics
		variables["REQUEST_METHOD"] = method
		variables["REQUEST_URI"] = r.RequestURI
		variables["QUERY_STRING"] = r.URL.RawQuery

		// Query args
		qParams, _ := url.ParseQuery(r.URL.RawQuery)
		for k, v := range qParams {
			variables["ARGS:"+k] = strings.Join(v, ",")
		}

		// Body
		var bodyBytes []byte
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			bodyBytes, _ = io.ReadAll(r.Body)
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			variables["REQUEST_BODY"] = string(bodyBytes)

			_ = r.ParseForm()
			for k, v := range r.PostForm {
				variables["ARGS:"+k] = strings.Join(v, ",")
			}
		}

		// Headers
		for k, v := range r.Header {
			if len(v) > 0 {
				variables["REQUEST_HEADERS:"+strings.ToLower(k)] = v[0]
			}
		}

		// Cookies
		for _, c := range r.Cookies() {
			variables["REQUEST_COOKIES:"+c.Name] = c.Value
		}

		// Convert to Request struct
		req := &Request{
			Method:  variables["REQUEST_METHOD"],
			Path:    variables["REQUEST_URI"],
			Query:   make(map[string][]string),
			Headers: make(map[string]string),
			Body:    make(map[string]any),
		}

		for k, v := range variables {
			switch {
			case strings.HasPrefix(k, "ARGS:"):
				name := strings.TrimPrefix(k, "ARGS:")
				req.Query[name] = []string{v}
				req.Body[name] = v
			case strings.HasPrefix(k, "REQUEST_HEADERS:"):
				name := strings.ToLower(strings.TrimPrefix(k, "REQUEST_HEADERS:"))
				req.Headers[name] = v
			case strings.HasPrefix(k, "REQUEST_COOKIES:"):
				req.Body[k] = v
			case k == "REQUEST_BODY":
				req.Body["_raw"] = v
			}
		}

		// Inspect request
		dec := eval.InspectPhases(req)

		if dec.Block {
			http.Error(w, dec.Message, http.StatusForbidden)
			return
		}

		fmt.Fprintf(w, "✅ Allowed. Score=%d\n%s", dec.Score, dec.Message)
	})
}

// ==========================
// expandVariable helper
// ==========================
func (e *Evaluator) expandVariable(variable string, req *Request) []string {
	var out []string
	upper := strings.ToUpper(variable)

	switch {
	case upper == "ARGS":
		for _, vs := range req.Query {
			out = append(out, vs...)
		}
		for _, v := range req.Body {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	case upper == "ARGS_NAMES":
		for k := range req.Query {
			out = append(out, k)
		}
		for k := range req.Body {
			out = append(out, k)
		}
	case upper == "REQUEST_BODY":
		if raw, ok := req.Body["_raw"].(string); ok {
			out = append(out, raw)
		}
	case strings.HasPrefix(upper, "REQUEST_HEADERS"):
		if idx := strings.Index(variable, ":"); idx > -1 {
			name := strings.TrimSpace(variable[idx+1:])
			if v, ok := req.Headers[strings.ToLower(name)]; ok {
				out = append(out, v)
			}
		} else {
			for _, v := range req.Headers {
				out = append(out, v)
			}
		}
	case strings.HasPrefix(upper, "REQUEST_COOKIES"):
		if idx := strings.Index(variable, ":"); idx > -1 {
			name := strings.TrimSpace(variable[idx+1:])
			for k, v := range req.Body {
				if strings.HasPrefix(k, "REQUEST_COOKIES:"+name) {
					if s, ok := v.(string); ok {
						out = append(out, s)
					}
				}
			}
		} else {
			for k, v := range req.Body {
				if strings.HasPrefix(k, "REQUEST_COOKIES:") {
					if s, ok := v.(string); ok {
						out = append(out, s)
					}
				}
			}
		}
	case upper == "REQUEST_URI":
		out = append(out, req.Path)
	default:
		for _, v := range req.Headers {
			out = append(out, v)
		}
		for _, vs := range req.Query {
			out = append(out, vs...)
		}
		for _, v := range req.Body {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
