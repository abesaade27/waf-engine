package main

import (
	"encoding/json"
	"fmt"
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

// Final JSON response struct (no matched_rules array anymore)
type WAFResponse struct {
	Decision     string `json:"decision"`      // "allow" or "block"
	Score        int    `json:"score"`         // total score
	MatchedCount int    `json:"matched_count"` // number of rules matched
}

// ==========================
// Evaluator + Constructor
// ==========================
type Evaluator struct {
	rules []rules.Rule
}

func NewEvaluator(rules []rules.Rule) *Evaluator {
	fmt.Println("🔹 [DEBUG] NewEvaluator initialized with rules:", len(rules))
	return &Evaluator{rules: rules}
}

// ==========================
// InspectPhases (CRS style with variable expansion)
// ==========================
func (e *Evaluator) InspectPhases(req *Request) (Decision, []utils.MatchedRuleLog) {
	fmt.Println("\n🔹 [DEBUG] InspectPhases called")
	fmt.Printf("   Method=%s Path=%s\n", req.Method, req.Path)

	dec := Decision{Block: false, Score: 0, Message: ""}
	firedRules := make(map[string]bool)
	matchedRules := []utils.MatchedRuleLog{}

	for _, rule := range e.rules {
		if rule.Compiled == nil {
			fmt.Printf("   ⚠️ Skipping Rule %s (no compiled regex)\n", rule.ID)
			continue
		}

		fmt.Printf("\n=== Rule Evaluation ===\n")
		fmt.Printf("Rule ID: %s | Name: %s | Variable: %s | Regex: %s\n",
			rule.ID, rule.Name, rule.Variable, rule.Regex)

		varNames := strings.Split(rule.Variable, "|")
		for _, varName := range varNames {
			candidates := e.expandVariable(varName, req)
			fmt.Printf("   ↪ Variable %s expanded to %d candidates: %v\n", varName, len(candidates), candidates)

			for _, val := range candidates {
				if val == "" {
					continue
				}

				if rule.Compiled.MatchString(val) && !firedRules[rule.ID] {
					fmt.Printf("   ✅ MATCHED Rule %s (ID %s) on value: %s\n", rule.Name, rule.ID, val)
					firedRules[rule.ID] = true
					dec.Score++
					if rule.Block {
						dec.Block = true
					}

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
				} else {
					fmt.Printf("   ❌ No match for Rule %s (ID %s) on value: %s\n", rule.Name, rule.ID, val)
				}
			}
		}
	}

	fmt.Printf("✅ [DEBUG] InspectPhases finished. Score=%d Block=%v\n", dec.Score, dec.Block)
	return dec, matchedRules
}

// ==========================
// HTTPHandler (flatten and normalize correctly)
// ==========================
func HTTPHandler(eval *Evaluator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("\n================ New Request ================")

		// ✅ Use updated NormalizeHTTP (handles raw + JSON)
		method, headers, body := utils.NormalizeHTTP(r)
		fmt.Printf("🔹 [DEBUG] HTTPHandler received %s %s\n", method, r.RequestURI)

		req := &Request{
			Method:       method,
			Path:         r.RequestURI,
			Query:        make(map[string][]string),
			Headers:      headers,
			Body:         body, // only raw + JSON here
			FlattenCache: make(map[string][]string),
		}

		// ✅ Flatten normalized body
		req.FlattenCache["REQUEST_BODY"] = []string{utils.FlattenJSON(body)}

		// ✅ Query parameters (only in Query + FlattenCache, not in Body)
		qParams, _ := url.ParseQuery(r.URL.RawQuery)
		for k, v := range qParams {
			req.Query[k] = v
			req.FlattenCache["ARGS:"+k] = v
			fmt.Printf("   ↪ Parsed query param %s=%v\n", k, v)
		}

		// ✅ Headers
		for k, v := range headers {
			req.FlattenCache["REQUEST_HEADERS:"+k] = []string{v}
			fmt.Printf("   ↪ Header %s=%s\n", k, v)
		}

		// ✅ Cookies
		for _, c := range r.Cookies() {
			req.FlattenCache["REQUEST_COOKIES:"+c.Name] = []string{c.Value}
			fmt.Printf("   🍪 Cookie %s=%s\n", c.Name, c.Value)
		}

		// ✅ Request URI
		req.FlattenCache["REQUEST_URI"] = []string{req.Path}
		fmt.Printf("   🌐 Request URI stored: %s\n", req.Path)

		// Inspect request
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

		// Build JSON response
		resp := WAFResponse{
			Decision: func() string {
				if dec.Block {
					return "block"
				}
				return "allow"
			}(),
			Score:        dec.Score,
			MatchedCount: len(matchedRules),
		}

		// Always return JSON to reverse proxy
		w.Header().Set("Content-Type", "application/json")
		if dec.Block {
			fmt.Println("🚫 [DEBUG] Blocking request due to rule match")
			w.WriteHeader(http.StatusForbidden)
		} else {
			fmt.Printf("✅ [DEBUG] Allowed request. Final Score=%d, Matches=%d\n", dec.Score, len(matchedRules))
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// ==========================
// expandVariable helper
// ==========================
func (e *Evaluator) expandVariable(variable string, req *Request) []string {
	upper := strings.ToUpper(variable)
	fmt.Printf("   🔎 [DEBUG] expandVariable called for %s\n", variable)

	switch {
	case upper == "ARGS":
		var out []string
		for k, vs := range req.FlattenCache {
			if strings.HasPrefix(k, "ARGS:") || (strings.HasPrefix(k, "BODY:") && k != "_raw") {
				out = append(out, vs...)
			}
		}
		return out

	case upper == "ARGS_NAMES":
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
		var out []string
		for _, vs := range req.FlattenCache {
			out = append(out, vs...)
		}
		return out
	}
}
