/*
WAF Utilities for Logging

This package provides helper functions for logging and other WAF utilities.

Key components:

1. WAFLogger (*log.Logger)
  - Global logger instance used by the WAF.
  - Writes logs to both console (stdout) and file (waf.log).

2. InitWAFLogger()
  - Initializes the WAFLogger.
  - Opens or creates `waf.log` in append mode.
  - Uses io.MultiWriter to log simultaneously to file and console.
  - Ensures clean log output without Go default prefixes (file:line).

3. LogEvent(eventType, clientIP, method, uri, msg string)
  - Formats a WAF log entry with timestamp, event type, client IP, HTTP method, URI, and custom message.
  - Example log:
    [2025-08-15 00:00:00] [ALERT] ClientIP=127.0.0.1 Method=POST URI=/login Details=[Matched Rule 942440] SQL Injection Detected
  - Used for recording alerts, anomalies, and informational messages.

Usage:
- Call InitWAFLogger() at WAF startup to initialize logging.
- Use LogEvent(...) throughout WAF code to log detections and events consistently.
*/
package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

var WAFLogger *log.Logger

// InitWAFLogger sets up logging to both file and console
func InitWAFLogger() {
	// Create or open waf.log
	file, err := os.OpenFile("waf.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("❌ Failed to open log file: %v", err)
	}

	// MultiWriter → writes to both file and console
	multiWriter := io.MultiWriter(file, os.Stdout)

	// Create logger (no waf.go:lineNumber clutter)
	WAFLogger = log.New(multiWriter, "", 0)
}

// LogEvent formats and prints a clean WAF log entry
func LogEvent(eventType, clientIP, method, uri, msg string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] [%s] ClientIP=%s Method=%s URI=%s Details=%s",
		timestamp, eventType, clientIP, method, uri, msg)
	WAFLogger.Println(logLine)
}
