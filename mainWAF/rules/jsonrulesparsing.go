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
