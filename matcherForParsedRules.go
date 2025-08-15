/*
WAF Request Inspector and Rule Matcher

This file provides the core logic to inspect incoming HTTP requests
against custom YAML-based WAF rules. Key components:

1. Rule struct:
  - Represents a single WAF rule after parsing from YAML.
  - Includes Target(s), Operator (regex or phrase match), Pattern, Phase, and Transformations.

2. applyTransformations():
  - Applies basic transformations (e.g., lowercase, URL decode, trim)
    to request values before matching, similar to CRS behavior.

3. MatchRule():
  - Checks a single request element (header, URI, or body field)
    against all loaded rules for a given phase.
  - Supports regex (@rx) and phrase matching (@pm).

4. flattenJSON():
  - Converts nested JSON request bodies into a flat key=value map
    using dot notation (e.g., user.name, items[0]).

5. inspectRequest():
  - Main inspection function.
  - Phase 1: Inspects request headers and URI.
  - Phase 2: Inspects JSON body fields after flattening.
  - Returns a list of matched rules/messages for logging or blocking.

Usage:
- Populate `LoadedRules` with rules parsed from YAML.
- Call `inspectRequest(r)` inside your WAF handler to detect anomalies.
*/
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Rule struct produced by your YAML parser
type Rule struct {
	ID              string
	Phase           int
	Target          []string // e.g. ["REQUEST_HEADERS", "ARGS", "REQUEST_BODY"]
	Operator        string   // e.g. "@rx", "@pm"
	Pattern         string   // regex or phrase
	Transformations []string
}

// Global loaded rules (populated from parser.go)
var LoadedRules []Rule

// Apply transformations like lowercase, urlDecode, trim
func applyTransformations(value string, transformations []string) string {
	for _, t := range transformations {
		switch t {
		case "lowercase":
			value = strings.ToLower(value)
		case "urlDecode":
			value, _ = url.QueryUnescape(value)
		case "trim":
			value = strings.TrimSpace(value)
		}
	}
	return value
}

// MatchRule checks a single target value against all loaded rules
func MatchRule(target string, value string, phase int) bool {
	for _, rule := range LoadedRules {
		if rule.Phase != phase {
			continue
		}

		matchTarget := false
		for _, t := range rule.Target {
			if strings.EqualFold(t, target) || strings.HasPrefix(target, t+":") {
				matchTarget = true
				break
			}
		}
		if !matchTarget {
			continue
		}

		transformedValue := applyTransformations(value, rule.Transformations)

		switch rule.Operator {
		case "@rx":
			re := regexp.MustCompile(rule.Pattern)
			if re.MatchString(transformedValue) {
				return true
			}
		case "@pm":
			phrases := strings.Split(rule.Pattern, " ")
			for _, phrase := range phrases {
				if strings.Contains(transformedValue, phrase) {
					return true
				}
			}
		}
	}
	return false
}

// Flatten nested JSON into dot.notation keys
func flattenJSON(data map[string]interface{}, prefix string, result map[string]string) {
	for key, value := range data {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := value.(type) {
		case map[string]interface{}:
			flattenJSON(v, fullKey, result)
		case []interface{}:
			for i, elem := range v {
				result[fullKey+"["+strconv.Itoa(i)+"]"] = fmt.Sprintf("%v", elem)
			}
		default:
			result[fullKey] = fmt.Sprintf("%v", v)
		}
	}
}

// inspectRequest applies phase 1 + phase 2 rules
func inspectRequest(r *http.Request) (matches []string) {
	// ---- Phase 1: HEADERS + URI ----
	for name, values := range r.Header {
		for _, v := range values {
			if MatchRule("REQUEST_HEADERS:"+name, v, 1) {
				matches = append(matches, "Header match: "+name+"="+v)
			}
		}
	}
	if MatchRule("URI", r.RequestURI, 1) {
		matches = append(matches, "URI match: "+r.RequestURI)
	}

	// ---- Phase 2: BODY (JSON) ----
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body.Close()

		// Reset body so backend can read it
		r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

		var jsonData map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &jsonData); err == nil {
			flat := make(map[string]string)
			flattenJSON(jsonData, "", flat)

			for key, value := range flat {
				if MatchRule("REQUEST_BODY:"+key, value, 2) {
					matches = append(matches, "Body match: "+key+"="+value)
				}
			}
		}
	}

	return matches
}
