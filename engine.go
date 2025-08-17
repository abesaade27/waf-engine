package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"waf-engine/mainWAF/rules"
	"waf-engine/mainWAF/utils"
)

type Request struct {
	Method       string
	Path         string
	Query        map[string][]string
	Headers      map[string]string
	Body         map[string]any
	FlattenCache map[string][]string
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
	return &Evaluator{rules: rules} // no regex compilation here
}

// ==========================
// InspectPhases (CRS style with variable expansion)
// ==========================
func (e *Evaluator) InspectPhases(req *Request) (Decision, []utils.MatchedRuleLog) {
	dec := Decision{Block: false, Score: 0, Message: ""}
	firedRules := make(map[string]bool)
	matchedRules := []utils.MatchedRuleLog{}

	for _, rule := range e.rules {
		if rule.Compiled == nil { // skip rules without a compiled regex
			continue
		}

		varNames := strings.Split(rule.Variable, "|")
		for _, varName := range varNames {
			candidates := e.expandVariable(varName, req)
			for _, val := range candidates {
				if val == "" {
					continue
				}

				// ✅ use precompiled regex
				if rule.Compiled.MatchString(val) && !firedRules[rule.ID] {
					firedRules[rule.ID] = true
					dec.Score++
					if rule.Block {
						dec.Block = true
					}

					// Append structured log for all matches
					matchedRules = append(matchedRules, utils.MatchedRuleLog{
						RuleID:   rule.ID,
						RuleName: rule.Name,
						Variable: varName,
						Block:    rule.Block,
						Description: fmt.Sprintf("%s by rule %s: %s in %s",
							func() string {
								if rule.Block {
									return "🚫 Blocked"
								} else {
									return "⚠️ Detected"
								}
							}(),
							rule.ID, rule.Name, varName),
					})
				}
			}
		}
	}

	// Optional: populate dec.Message only for client response if needed
	// dec.Message = "" // could leave empty if client doesn't need detailed messages

	return dec, matchedRules
}

// ==========================
// HTTPHandler (flatten and normalize correctly)
// ==========================
// ==========================
// HTTPHandler (flatten and normalize correctly)
// ==========================
func HTTPHandler(eval *Evaluator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, _, _, _, _ := utils.NormalizeHTTP(r)

		req := &Request{
			Method:       method,
			Path:         r.RequestURI,
			Query:        make(map[string][]string),
			Headers:      make(map[string]string),
			Body:         make(map[string]any),
			FlattenCache: make(map[string][]string),
		}

		// Query parameters
		qParams, _ := url.ParseQuery(r.URL.RawQuery)
		for k, v := range qParams {
			req.Query[k] = v
			req.Body[k] = strings.Join(v, ",")
			req.FlattenCache["ARGS:"+k] = v
		}

		// Body
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			bodyBytes, _ := io.ReadAll(r.Body)
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			req.Body["_raw"] = string(bodyBytes)
			req.FlattenCache["REQUEST_BODY"] = []string{string(bodyBytes)}

			_ = r.ParseForm()
			for k, v := range r.PostForm {
				req.Query[k] = v
				req.FlattenCache["ARGS:"+k] = v
			}
		}

		// Headers
		for k, v := range r.Header {
			if len(v) > 0 {
				req.Headers[strings.ToLower(k)] = v[0]
				req.FlattenCache["REQUEST_HEADERS:"+strings.ToLower(k)] = []string{v[0]}
			}
		}

		// Cookies
		for _, c := range r.Cookies() {
			req.Body["REQUEST_COOKIES:"+c.Name] = c.Value
			req.FlattenCache["REQUEST_COOKIES:"+c.Name] = []string{c.Value}
		}

		// Request URI
		req.FlattenCache["REQUEST_URI"] = []string{req.Path}

		// Inspect request and get structured logs
		dec, matchedRules := eval.InspectPhases(req)

		// Structured logging
		utils.LogRequest(
			r.RemoteAddr,
			req.Method,
			req.Path,
			matchedRules,
			dec.Score,
			dec.Block,
		)

		// Respond to client using structured info
		if dec.Block {
			http.Error(w, "🚫 Request blocked by WAF", http.StatusForbidden)
			return
		}

		fmt.Fprintf(w, "✅ Allowed. Score=%d. MatchedRules=%d", dec.Score, len(matchedRules))
	})
}

// ==========================
// expandVariable helper
// ==========================
func (e *Evaluator) expandVariable(variable string, req *Request) []string {
	upper := strings.ToUpper(variable)

	switch {
	case upper == "ARGS":
		// Return all argument values from ARGS: and BODY: keys (excluding _raw)
		var out []string
		for k, vs := range req.FlattenCache {
			if strings.HasPrefix(k, "ARGS:") || (strings.HasPrefix(k, "BODY:") && k != "_raw") {
				out = append(out, vs...)
			}
		}
		return out

	case upper == "ARGS_NAMES":
		// Return all argument names (without prefix) from ARGS: and BODY:
		var out []string
		for k := range req.FlattenCache {
			if strings.HasPrefix(k, "ARGS:") || (strings.HasPrefix(k, "BODY:") && k != "_raw") {
				name := strings.TrimPrefix(k, "ARGS:")
				name = strings.TrimPrefix(name, "BODY:")
				out = append(out, name)
			}
		}
		return out

	case upper == "REQUEST_BODY":
		return req.FlattenCache["_raw"]

	case strings.HasPrefix(upper, "REQUEST_HEADERS"), strings.HasPrefix(upper, "REQUEST_COOKIES"):
		if vals, ok := req.FlattenCache[variable]; ok {
			return vals
		}
		return nil

	case upper == "REQUEST_URI":
		return req.FlattenCache["REQUEST_URI"]

	default:
		// fallback: return all flattened values
		var out []string
		for _, vs := range req.FlattenCache {
			out = append(out, vs...)
		}
		return out
	}
}
