package main

import (
	"fmt"
	"net/http"

	"waf-engine/mainWAF/rules"
	"waf-engine/mainWAF/utils"
)

func wafHandler(w http.ResponseWriter, r *http.Request) {
	tx := &rules.Transaction{}

	// Only process POST/PUT bodies
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		normalizedHeaders, extractedBody, err := utils.PreprocessJSONReader(r.Body)
		if err != nil {
			http.Error(w, "Invalid JSON input: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Scan normalized headers
		for name, val := range normalizedHeaders {
			checkAgainstRules(tx, "HEADERS:"+name, val)
		}

		// Scan extracted body string fields
		for key, val := range extractedBody {
			if strVal, ok := val.(string); ok {
				checkAgainstRules(tx, "BODY:"+key, strVal)
			}
		}
	}

	// Scan URL query parameters (as before)
	for name, vals := range r.URL.Query() {
		for _, val := range vals {
			checkAgainstRules(tx, "ARGS:"+name, val)
		}
	}

	// Decision logic unchanged
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

func checkAgainstRules(tx *rules.Transaction, variable, value string) {
	for _, rule := range allRules {
		if utils.MatchRegex(rule.Regex, value) {
			msg := fmt.Sprintf("[Matched Rule %s] %s in %s: %q", rule.ID, rule.Name, variable, value)
			utils.WAFLogger.Println(msg) // log file
			fmt.Println(msg)             // console

			tx.InboundAnomalyScorePL1++ // simple scoring
			if rule.Block {
				tx.Block = true
			}
		}
	}
}
