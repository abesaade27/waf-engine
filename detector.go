package main

import (
	"fmt"
	"waf-engine/mainWAF/rules"
	"waf-engine/mainWAF/utils"
)

func CheckAgainstRules(tx *Transaction, variable, value string) {
	for _, rule := range rules.AllRules {
		if utils.MatchRegex(rule.Regex, value) {
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
		}
	}
}
