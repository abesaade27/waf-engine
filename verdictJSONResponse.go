/*
WAF Verdict Response

This file defines the structure and helper function to send
JSON verdicts from the WAF to the reverse proxy or client.

1. WAFVerdict struct:
   - Represents the JSON response sent after inspecting a request.
   - Fields:
     - Verdict: "allowed", "blocked", or "error"
     - Score: WAF anomaly score (integer)
     - Blocked: true if the request is blocked
     - Reason: optional string explaining why the request was blocked
     - StatusCode: HTTP response code

2. sendJSONVerdict():
   - Helper function to write a WAFVerdict as JSON to the ResponseWriter.
   - Sets Content-Type header and HTTP status code.
   - Used by WAF handlers after processing requests.

Usage:
- Call sendJSONVerdict() after applying rules to return the verdict to the client or reverse proxy.
*/

package main

import (
	"encoding/json"
	"net/http"
)

// WAFVerdict is the JSON format returned to reverse proxy
type WAFVerdict struct {
	Verdict    string `json:"verdict"` // allowed / blocked / error
	Score      int    `json:"score"`   // WAF score
	Blocked    bool   `json:"blocked"` // true if blocked
	Reason     string `json:"reason,omitempty"`
	StatusCode int    `json:"status_code"` // HTTP status
}

// sendJSONVerdict writes a JSON verdict response
func sendJSONVerdict(w http.ResponseWriter, statusCode int, verdict string, score int, blocked bool, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(WAFVerdict{
		Verdict:    verdict,
		Score:      score,
		Blocked:    blocked,
		Reason:     reason,
		StatusCode: statusCode,
	})
}
