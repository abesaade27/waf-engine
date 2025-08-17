package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"waf-engine/mainWAF/rules"
	"waf-engine/mainWAF/utils"
)

func main() {
	utils.InitLogger()

	// Load parsed rules directly
	err := rules.LoadRules("parsed_rules")
	if err != nil {
		log.Fatalf("❌ Failed to load rules: %v", err)
	}
	log.Printf("✅ Loaded %d rules", len(rules.AllRules))

	// Build engine with global rules
	enf := NewEvaluator(rules.AllRules)

	// Setup HTTP mux with WAF handler
	mux := http.NewServeMux()
	mux.Handle("/", HTTPHandler(enf))

	// Start server
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	fmt.Println("🚀 WAF listening on :8080")
	log.Fatal(srv.ListenAndServe())
}
