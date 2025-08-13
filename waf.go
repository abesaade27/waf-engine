package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"waf-engine/mainWAF/rules"
	"waf-engine/mainWAF/utils"
)

// helper to get IP from RemoteAddr (can be improved if behind proxies)
func getClientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // fallback to raw string
	}
	return ip
}

func wafHandler(w http.ResponseWriter, r *http.Request) {
	tx := &rules.Transaction{}

	// 1) Normalize real HTTP headers (always inspect these)
	realHeaders := utils.NormalizeHeaders(r.Header)

	// build final headers map merging realHeaders and JSON headers (JSON overrides)
	finalHeaders := make(map[string]string)
	for k, v := range realHeaders {
		finalHeaders[k] = v
	}

	// 2) Read body safely (limit enforced in PreprocessJSONReader, but we still read here for parsing/fallback)
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, utils.MaxJSONSize))
	if err != nil {
		http.Error(w, "Failed to read request body: "+err.Error(), http.StatusInternalServerError)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// 3) If Content-Type is JSON, try to parse structured input from proxy
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") && len(bodyBytes) > 0 {
		normHeadersJSON, extractedBody, err := utils.PreprocessJSONReader(bytes.NewReader(bodyBytes))
		if err != nil {
			log.Printf("PreprocessJSONReader error: %v", err)
		} else {
			for k, v := range normHeadersJSON {
				finalHeaders[k] = v
			}

			for name, val := range finalHeaders {
				checkAgainstRules(tx, "HEADERS:"+name, val, r)
				if tx.Block {
					break // stop scanning if blocked
				}
			}

			if !tx.Block {
				for key, val := range extractedBody {
					if strVal, ok := val.(string); ok {
						checkAgainstRules(tx, "BODY:"+key, strVal, r)
						if tx.Block {
							break
						}
					}
				}
			}
		}
	}

	if !tx.Block && !(strings.Contains(ct, "application/json") && len(bodyBytes) > 0) {
		for name, val := range finalHeaders {
			checkAgainstRules(tx, "HEADERS:"+name, val, r)
			if tx.Block {
				break
			}
		}

		if !tx.Block && len(bodyBytes) > 0 {
			checkAgainstRules(tx, "BODY", string(bodyBytes), r)
		}
	}

	// 4) Scan URL query parameters
	if !tx.Block {
		for name, vals := range r.URL.Query() {
			for _, val := range vals {
				checkAgainstRules(tx, "ARGS:"+name, val, r)
				if tx.Block {
					break
				}
			}
			if tx.Block {
				break
			}
		}
	}

	// Decision logic
	if tx.Block {
		http.Error(w, "🔒 Malicious Request Blocked", http.StatusForbidden)
		return
	}

	const threshold = 5
	tx.CalculateCriticalScore()
	if tx.CriticalAnomalyScore >= threshold {
		http.Error(w, "🚫 Request blocked by WAF (score too high)", http.StatusForbidden)
		return
	}

	fmt.Fprintf(w, "✅ Safe. Score: %d", tx.InboundAnomalyScorePL1)
}

var LogAllMatches = false // toggle in config

func checkAgainstRules(tx *rules.Transaction, variable, value string, r *http.Request) {
	if value == "" {
		return
	}

	clientIP := getClientIP(r)

	for _, rule := range rules.AllRules {
		if utils.MatchRegex(rule.Regex, value) {
			msg := fmt.Sprintf("[Matched Rule %s] %s in %s: %q",
				rule.ID, rule.Name, variable, value)
			utils.LogEvent("ALERT", clientIP, r.Method, r.URL.Path, msg)

			tx.InboundAnomalyScorePL1++

			if rule.Block {
				tx.Block = true
				if !LogAllMatches {
					return
				}
			}
		}
	}
}

func main() {
	utils.InitWAFLogger()
	utils.WAFLogger.Println("WAF Logger initialized successfully")

	rules.LoadAllRules("parsed_rules")

	http.HandleFunc("/", wafHandler)
	fmt.Println("🚀 WAF running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// func checkAgainstRules(tx *rules.Transaction, variable, value string, r *http.Request) {
// 	if value == "" {
// 		return
// 	}

// 	clientIP := getClientIP(r)

// 	for _, rule := range rules.AllRules {
// 		if utils.MatchRegex(rule.Regex, value) {
// 			msg := fmt.Sprintf("[Matched Rule %s] %s in %s: %q", rule.ID, rule.Name, variable, value)
// 			utils.LogEvent("ALERT", clientIP, r.Method, r.URL.Path, msg)

// 			tx.InboundAnomalyScorePL1++

// 			if rule.Block {
// 				tx.Block = true
// 				return
// 			}
// 		}
// 	}
// }
