package utils

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

// Logger is global
var Logger *log.Logger

// MatchedRuleLog represents a structured log entry for a single matched rule
type MatchedRuleLog struct {
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Variable    string `json:"variable"`
	Severity    string `json:"severity"`
	Block       bool   `json:"block"`
	Description string `json:"description"`
}

// RequestLog represents the full request log
type RequestLog struct {
	Timestamp    string           `json:"timestamp"`
	ClientIP     string           `json:"client_ip"`
	Method       string           `json:"method"`
	URI          string           `json:"uri"`
	MatchedRules []MatchedRuleLog `json:"matched_rules"`
	TotalScore   int              `json:"total_score"`
	Blocked      bool             `json:"blocked"`
}

// InitLogger initializes the global logger
func InitLogger() {
	file, err := os.OpenFile("waf.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("Failed to open waf.log:", err)
	}
	Logger = log.New(file, "[WAF] ", log.LstdFlags)
}

// LogRequest logs a request in structured JSON format
func LogRequest(clientIP, method, uri string, matchedRules []MatchedRuleLog, totalScore int, blocked bool) {
	logEntry := RequestLog{
		Timestamp:    time.Now().Format(time.RFC3339),
		ClientIP:     clientIP,
		Method:       method,
		URI:          uri,
		MatchedRules: matchedRules,
		TotalScore:   totalScore,
		Blocked:      blocked,
	}

	data, err := json.Marshal(logEntry)
	if err != nil {
		Logger.Printf("❌ Failed to marshal request log: %v", err)
		return
	}

	Logger.Println(string(data))
}
