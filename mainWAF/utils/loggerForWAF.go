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
