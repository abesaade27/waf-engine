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

	// 1️⃣ Load parsed rules directly
	err := rules.LoadRules("parsed_rules")
	if err != nil {
		log.Fatalf("❌ Failed to load rules: %v", err)
	}
	log.Printf("✅ Loaded %d rules", len(rules.AllRules))

	// 2️⃣ Build engine with global rules and precompiled regex
	enf := NewEvaluator(rules.AllRules)

	// 3️⃣ Setup HTTP mux with WAF handler
	mux := http.NewServeMux()
	mux.Handle("/", HTTPHandler(enf))

	// 4️⃣ Start server
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	fmt.Println("🚀 WAF listening on :8080")
	log.Fatal(srv.ListenAndServe())
}
