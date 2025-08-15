/*
Rules Loader for WAF

This package handles loading parsed YAML rules into memory for the WAF.

Key components:

1. Rule struct:
  - Represents a single rule loaded from YAML.
  - Fields: ID, Name, Variable (target), Regex pattern, Phase, Severity, Block flag.

2. AllRules slice:
  - Holds all loaded rules in memory.
  - Exported so other WAF packages (like waf.go) can iterate and apply rules.

3. LoadAllRules(dir string):
  - Clears the regex cache in utils to avoid stale compiled patterns.
  - Clears the in-memory AllRules slice.
  - Reads all `.yaml` files in the given directory.
  - Parses YAML contents into Rule structs.
  - Appends all rules to AllRules for WAF inspection.
  - Logs warnings if files cannot be read or parsed.
  - Logs the total number of rules loaded.

Usage:
- Call LoadAllRules("parsed_rules") during WAF startup or for hot-reloading rules.
- Ensures the WAF always uses the latest rules without restarting the server.
*/
package rules

import (
	"log"
	"os"
	"path/filepath"

	"waf-engine/mainWAF/utils" // import your utils for regex cache

	"gopkg.in/yaml.v3"
)

type Rule struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Variable string `yaml:"variable"`
	Regex    string `yaml:"regex"`
	Phase    int    `yaml:"phase"`
	Severity string `yaml:"severity"`
	Block    bool   `yaml:"block"`
}

// Exported so other packages can iterate loaded rules
var AllRules []Rule

// LoadAllRules loads YAML rules and clears regex cache for hot-reload
func LoadAllRules(dir string) {
	// Step 1: Clear regex cache so we don't reuse stale compiled patterns
	utils.ClearRegexCache()

	// Step 2: Clear in-memory rules
	AllRules = nil

	// Step 3: Load new YAML rules
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		log.Fatalf("❌ Failed to read rules dir: %v", err)
	}

	if len(files) == 0 {
		log.Printf("⚠️ No YAML rule files found in %s", dir)
		return
	}

	for _, file := range files {
		log.Printf("📄 Loading rules from: %s", filepath.Base(file))

		data, err := os.ReadFile(file)
		if err != nil {
			log.Printf("⚠️ Could not read %s: %v", file, err)
			continue
		}

		var rules []Rule
		if err := yaml.Unmarshal(data, &rules); err != nil {
			log.Printf("⚠️ Could not parse %s: %v", file, err)
			continue
		}

		AllRules = append(AllRules, rules...)
	}

	log.Printf("✅ Loaded %d rules from %s", len(AllRules), dir)
}
