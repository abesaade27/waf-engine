package main

import (
	"bytes"
	"encoding/json"
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
	allowed, reason := InspectRequest(r)

	if allowed {
		utils.LogEvent(
			"INFO",
			r.RemoteAddr,
			r.Method,
			r.RequestURI,
			"Request allowed",
		)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "allowed",
		})
	} else {
		utils.LogEvent(
			"ALERT",
			r.RemoteAddr,
			r.Method,
			r.RequestURI,
			reason,
		)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "blocked",
			"reason": reason,
		})
	}
}

func InspectRequest(r *http.Request) (bool, string) {
	// Collect request data for inspection
	inputs := map[string]string{}

	// Headers
	for k, v := range r.Header {
		inputs["REQUEST_HEADERS:"+strings.ToLower(k)] = strings.Join(v, ",")
	}

	// Query params
	for k, v := range r.URL.Query() {
		inputs["ARGS:"+k] = strings.Join(v, ",")
	}

	// Body (try JSON first, then plain)
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // reset body

		var jsonData map[string]interface{}
		if json.Unmarshal(bodyBytes, &jsonData) == nil {
			flat := map[string]string{}
			utils.FlattenJSON(jsonData, "", flat)
			for k, v := range flat {
				inputs["JSON:"+k] = v
			}
		} else {
			inputs["REQUEST_BODY"] = string(bodyBytes)
		}
	}

	// Check against rules
	for _, rule := range rules.AllRules {
		for inputKey, inputVal := range inputs {
			if matchesRuleVariable(inputKey, rule.Variable) {
				if utils.MatchRegex(rule.Regex, inputVal) {
					return false, fmt.Sprintf("Matched Rule %s - %s", rule.ID, rule.Name)
				}
			}
		}
	}

	return true, "No matches"
}

var LogAllMatches = true // log all matches or block on first match

//var LogAllMatches = false //block on first match

// do we need to block on first match or log all matches?

func matchesRuleVariable(inputVar, ruleVar string) bool {
	inputVar = strings.ToUpper(strings.TrimSpace(inputVar))
	ruleVar = strings.ToUpper(strings.TrimSpace(ruleVar))

	// Support multiple alternatives with |
	for _, part := range strings.Split(ruleVar, "|") {
		part = strings.TrimSpace(part)

		if part == "*" {
			return true
		}

		// Exact match
		if part == inputVar {
			return true
		}

		// Wildcard suffix: REQUEST_HEADERS:* should match REQUEST_HEADERS:User-Agent
		if strings.HasSuffix(part, ":*") {
			prefix := strings.TrimSuffix(part, "*")
			if strings.HasPrefix(inputVar, prefix) {
				return true
			}
		}

		// Generic starts-with match for REQUEST_BODY matching REQUEST_BODY:username
		if strings.HasPrefix(inputVar, part+":") {
			return true
		}
	}
	return false
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
