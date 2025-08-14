// verdict.go
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
