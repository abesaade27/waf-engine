package utils

import (
	"log"
	"os"
)

var Logger *log.Logger

func InitLogger() {
	file, err := os.OpenFile("waf.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("Failed to open waf.log:", err)
	}
	Logger = log.New(file, "[WAF] ", log.LstdFlags)
}
