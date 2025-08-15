package main

// import (
// 	"fmt"
// 	"net/http"

// 	"waf-engine/mainWAF/rules"
// 	"waf-engine/mainWAF/utils"
// )

// func wafHandler(w http.ResponseWriter, r *http.Request) {
// 	tx := &rules.Transaction{}

// 	// Only process POST/PUT bodies
// 	if r.Method == http.MethodPost || r.Method == http.MethodPut {
// 		normalizedHeaders, extractedBody, err := utils.PreprocessJSONReader(r.Body)
// 		if err != nil {
// 			http.Error(w, "Invalid JSON input: "+err.Error(), http.StatusBadRequest)
// 			return
// 		}

// 		// Scan normalized headers
// 		for name, val := range normalizedHeaders {
// 			checkAgainstRules(tx, "HEADERS:"+name, val)
// 		}

// 		// Scan extracted body string fields
// 		for key, val := range extractedBody {
// 			if strVal, ok := val.(string); ok {
// 				checkAgainstRules(tx, "BODY:"+key, strVal)
// 			}
// 		}
// 	}

// 	// Scan URL query parameters (as before)
// 	for name, vals := range r.URL.Query() {
// 		for _, val := range vals {
// 			checkAgainstRules(tx, "ARGS:"+name, val)
// 		}
// 	}

// 	// Decision logic unchanged
// 	if tx.Block {
// 		http.Error(w, "🔒 Malicious Request Blocked", http.StatusForbidden)
// 		return
// 	}

// 	const threshold = 5
// 	tx.CalculateCriticalScore()
// 	if tx.CriticalAnomalyScore >= threshold {
// 		http.Error(w, "🚫 Request blocked by WAF (score too high)", http.StatusForbidden)
// 		return
// 	}

// 	fmt.Fprintf(w, "✅ Safe. Score: %d", tx.InboundAnomalyScorePL1)
// }

// func checkAgainstRules(tx *rules.Transaction, variable, value string) {
// 	for _, rule := range allRules {
// 		if utils.MatchRegex(rule.Regex, value) {
// 			msg := fmt.Sprintf("[Matched Rule %s] %s in %s: %q", rule.ID, rule.Name, variable, value)
// 			utils.WAFLogger.Println(msg) // log file
// 			fmt.Println(msg)             // console

// 			tx.InboundAnomalyScorePL1++ // simple scoring
// 			if rule.Block {
// 				tx.Block = true
// 			}
// 		}
// 	}
// }

// HANDLER ANALYZING BOTH RAW AND JSON FORMAT REQUESTS
//func wafHandler(w http.ResponseWriter, r *http.Request) {
// 	tx := &rules.Transaction{}
// 	realHeaders := utils.NormalizeHeaders(r.Header)

// 	finalHeaders := make(map[string]string)
// 	for k, v := range realHeaders {
// 		finalHeaders[k] = v
// 	}

// 	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, utils.MaxJSONSize))
// 	if err != nil {
// 		sendJSONVerdict(w, http.StatusInternalServerError, "error", 0, false, "Failed to read request body: "+err.Error())
// 		return
// 	}
// 	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

// 	ct := r.Header.Get("Content-Type")
// 	if strings.Contains(ct, "application/json") && len(bodyBytes) > 0 {
// 		normHeadersJSON, extractedBody, err := utils.PreprocessJSONReader(bytes.NewReader(bodyBytes))
// 		if err != nil {
// 			log.Printf("PreprocessJSONReader error: %v", err)
// 		} else {
// 			for k, v := range normHeadersJSON {
// 				finalHeaders[k] = v
// 			}
// 			for name, val := range finalHeaders {
// 				checkAgainstRules(tx, "HEADERS:"+name, val, r)
// 				if tx.Block {
// 					break
// 				}
// 			}
// 			if !tx.Block {
// 				for key, val := range extractedBody {
// 					if strVal, ok := val.(string); ok {
// 						checkAgainstRules(tx, "BODY:"+key, strVal, r)
// 						if tx.Block {
// 							break
// 						}
// 					}
// 				}
// 			}
// 		}
// 	}

// 	if !tx.Block && !(strings.Contains(ct, "application/json") && len(bodyBytes) > 0) {
// 		for name, val := range finalHeaders {
// 			checkAgainstRules(tx, "HEADERS:"+name, val, r)
// 			if tx.Block {
// 				break
// 			}
// 		}
// 		if !tx.Block && len(bodyBytes) > 0 {
// 			checkAgainstRules(tx, "BODY", string(bodyBytes), r)
// 		}
// 	}

// 	if !tx.Block {
// 		for name, vals := range r.URL.Query() {
// 			for _, val := range vals {
// 				checkAgainstRules(tx, "ARGS:"+name, val, r)
// 				if tx.Block {
// 					break
// 				}
// 			}
// 			if tx.Block {
// 				break
// 			}
// 		}
// 	}

// 	if tx.Block {
// 		sendJSONVerdict(w, http.StatusForbidden, "blocked", tx.InboundAnomalyScorePL1, true, "Malicious Request Blocked")
// 		return
// 	}

// 	const threshold = 5
// 	tx.CalculateCriticalScore()
// 	if tx.CriticalAnomalyScore >= threshold {
// 		sendJSONVerdict(w, http.StatusForbidden, "blocked", tx.InboundAnomalyScorePL1, true, "Score too high")
// 		return
// 	}

// 	sendJSONVerdict(w, http.StatusOK, "allowed", tx.InboundAnomalyScorePL1, false, "Safe Request")
// }

////////////////////////////////////////////////////////////////////

// func wafHandler(w http.ResponseWriter, r *http.Request) {
// 	tx := &rules.Transaction{}
// 	var matches []string

// 	// ---- Phase 1: Headers ----
// 	for name, values := range r.Header {
// 		for _, v := range values {
// 			checkAgainstRules(tx, "REQUEST_HEADERS:"+strings.ToLower(name), v, r)
// 			if MatchRule("REQUEST_HEADERS:"+strings.ToLower(name), v, 1) {
// 				matches = append(matches, fmt.Sprintf("Header match: %s=%s", name, v))
// 			}
// 			if tx.Block {
// 				break
// 			}
// 		}
// 	}

// 	// ---- URI Check ----
// 	checkAgainstRules(tx, "URI", r.RequestURI, r)
// 	if MatchRule("URI", r.RequestURI, 1) {
// 		matches = append(matches, "URI match: "+r.RequestURI)
// 	}

// 	// ---- Phase 2: JSON body ----
// 	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
// 		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, utils.MaxJSONSize))
// 		if err != nil {
// 			sendJSONVerdict(w, http.StatusInternalServerError, "error", 0, false,
// 				"Failed to read request body: "+err.Error())
// 			return
// 		}
// 		r.Body = io.NopCloser(bytes.NewReader(bodyBytes)) // Restore for reverse proxy if needed

// 		if len(bodyBytes) > 0 {
// 			// Normalize headers & extract body
// 			normHeadersJSON, extractedBody, err := utils.PreprocessJSONReader(bytes.NewReader(bodyBytes))
// 			if err != nil {
// 				sendJSONVerdict(w, http.StatusBadRequest, "error", 0, false, "Invalid JSON format")
// 				return
// 			}

// 			// Check JSON headers
// 			for name, val := range normHeadersJSON {
// 				checkAgainstRules(tx, "REQUEST_HEADERS:"+strings.ToLower(name), val, r)
// 				if MatchRule("REQUEST_HEADERS:"+strings.ToLower(name), val, 1) {
// 					matches = append(matches, fmt.Sprintf("Header match: %s=%s", name, val))
// 				}
// 				if tx.Block {
// 					break
// 				}
// 			}

// 			// Check flattened JSON body
// 			if !tx.Block {
// 				for key, val := range extractedBody {
// 					if strVal, ok := val.(string); ok {
// 						checkAgainstRules(tx, "REQUEST_BODY:"+key, strVal, r)
// 						if MatchRule("REQUEST_BODY:"+key, strVal, 2) {
// 							matches = append(matches, fmt.Sprintf("Body match: %s=%s", key, strVal))
// 						}
// 						if tx.Block {
// 							break
// 						}
// 					}
// 				}
// 			}
// 		}
// 	}

// 	// ---- Final verdict ----
// 	block := tx.Block
// 	if !block {
// 		const threshold = 5
// 		tx.CalculateCriticalScore()
// 		if tx.CriticalAnomalyScore >= threshold {
// 			block = true
// 		}
// 	}

// 	if block || len(matches) > 0 {
// 		sendJSONVerdict(w, http.StatusForbidden, "blocked", tx.InboundAnomalyScorePL1, true,
// 			"Malicious Request: "+strings.Join(matches, "; "))
// 		return
// 	}

// 	sendJSONVerdict(w, http.StatusOK, "allowed", tx.InboundAnomalyScorePL1, false, "Safe Request")
//}
