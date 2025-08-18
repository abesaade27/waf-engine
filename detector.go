package main

import (
	"fmt"
	"waf-engine/mainWAF/rules"
	"waf-engine/mainWAF/utils"
)

func CheckAgainstRules(tx *Transaction, variable, value string) {
	for _, rule := range rules.AllRules {
		fmt.Printf("\n=== Rule Evaluation ===\n")
		fmt.Printf("Rule ID: %s | Name: %s | Variable: %s | Regex: %s\n", rule.ID, rule.Name, variable, rule.Regex)
		fmt.Printf("Target Value: %s\n", value)

		if utils.MatchRegex(rule.Regex, value) {
			fmt.Printf("✅ MATCHED Rule %s (ID %s) on value: %s\n", rule.Name, rule.ID, value)

			msg := fmt.Sprintf("[Rule %s] %s matched in %s: %q",
				rule.ID, rule.Name, variable, value)

			utils.Logger.Println(msg)
			tx.Matches = append(tx.Matches, msg)

			// scoring
			tx.Score++
			if rule.Severity == "CRITICAL" {
				tx.CriticalScore++
			}

			// blocking
			if rule.Block {
				tx.Block = true
			}
		} else {
			fmt.Printf("❌ No match for Rule %s (ID %s)\n", rule.Name, rule.ID)
		}
	}
}
