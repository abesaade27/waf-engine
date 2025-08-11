package utils

import (
	"io"
	"log"
	"os"
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

	// Create logger
	WAFLogger = log.New(multiWriter, "WAF: ", log.Ldate|log.Ltime|log.Lshortfile)
}
