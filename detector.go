package main

import (
	"fmt"
	"waf-engine/mainWAF/rules"
	"waf-engine/mainWAF/utils"
)

// value can be either string (single) or []string (like ARGS_NAMES)
func CheckAgainstRules(tx *Transaction, variable string, value interface{}) {
	for _, rule := range rules.AllRules {
		fmt.Printf("\n=== Rule Evaluation ===\n")
		fmt.Printf("Rule ID: %s | Name: %s | Variable: %s | Regex: %s\n", rule.ID, rule.Name, rule.Variable, rule.Regex)

		switch v := value.(type) {

		case string:
			fmt.Printf("Target Variable: %s | Extracted Value: %q\n", variable, v)
			if utils.MatchRegex(rule.Regex, v) {
				fmt.Printf("✅ MATCHED Rule %s (ID %s) on value: %s\n", rule.Name, rule.ID, v)
				logMatch(tx, rule, variable, v)
			} else {
				fmt.Printf("❌ No match for Rule %s (ID %s)\n", rule.Name, rule.ID)
			}

		case []string:
			fmt.Printf("Target Variable: %s | Extracted Values: %#v\n", variable, v)
			for _, one := range v {
				if utils.MatchRegex(rule.Regex, one) {
					fmt.Printf("✅ MATCHED Rule %s (ID %s) on value: %s\n", rule.Name, rule.ID, one)
					logMatch(tx, rule, variable, one)
				} else {
					fmt.Printf("❌ No match for Rule %s (ID %s) on value: %s\n", rule.Name, rule.ID, one)
				}
			}

		default:
			fmt.Printf("⚠️ Unsupported type for variable %s: %T\n", variable, v)
		}
	}
}

// helper function to record match
func logMatch(tx *Transaction, rule rules.Rule, variable, value string) {
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
