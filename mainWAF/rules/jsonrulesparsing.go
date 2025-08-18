package rules

import (
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

var allRules []Rule

func LoadAllRules(dir string) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		log.Fatalf("❌ Failed to read rules dir: %v", err)
	}

	for _, file := range files {
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

		allRules = append(allRules, rules...)
	}

	log.Printf("✅ Loaded %d rules from %s", len(allRules), dir)
}
