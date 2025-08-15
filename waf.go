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

func wafHandler(w http.ResponseWriter, r *http.Request) {
	tx := &rules.Transaction{}
	realHeaders := utils.NormalizeHeaders(r.Header)

	finalHeaders := make(map[string]string)
	for k, v := range realHeaders {
		finalHeaders[k] = v
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, utils.MaxJSONSize))
	if err != nil {
		sendJSONVerdict(w, http.StatusInternalServerError, "error", 0, false, "Failed to read request body: "+err.Error())
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

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
					break
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

	if tx.Block {
		sendJSONVerdict(w, http.StatusForbidden, "blocked", tx.InboundAnomalyScorePL1, true, "Malicious Request Blocked")
		return
	}

	const threshold = 5
	tx.CalculateCriticalScore()
	if tx.CriticalAnomalyScore >= threshold {
		sendJSONVerdict(w, http.StatusForbidden, "blocked", tx.InboundAnomalyScorePL1, true, "Score too high")
		return
	}

	sendJSONVerdict(w, http.StatusOK, "allowed", tx.InboundAnomalyScorePL1, false, "Safe Request")
}

var LogAllMatches = true

//var LogAllMatches =false

// do we need to block on first match or log all matches?

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

func getClientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func main() {
	utils.InitWAFLogger()
	utils.WAFLogger.Println("WAF Logger initialized successfully")
	rules.LoadAllRules("parsed_rules")
	http.HandleFunc("/", wafHandler)
	fmt.Println("🚀 WAF running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
