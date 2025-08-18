package rules

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Rule defines a single WAF rule structure
type Rule struct {
	ID         string         `yaml:"id"`
	Name       string         `yaml:"name"`
	Variable   string         `yaml:"variable"`
	Regex      string         `yaml:"regex"`
	Phase      int            `yaml:"phase"`
	Severity   string         `yaml:"severity"`
	Block      bool           `yaml:"block"`
	Transforms []string       `yaml:"transforms,omitempty"`
	Tags       []string       `yaml:"tags,omitempty"`
	Paranoia   int            `yaml:"paranoia_level,omitempty"`
	Controls   []string       `yaml:"controls,omitempty"`
	Chain      []Rule         `yaml:"chain,omitempty"`
	Compiled   *regexp.Regexp `yaml:"-"`
}

// AllRules holds every rule loaded from YAML
var AllRules []Rule

// LoadRules walks through a directory and loads all YAML rule files
func LoadRules(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("⚠️ Could not read %s: %v", path, err)
			return nil
		}

		var rules []Rule
		if err := yaml.Unmarshal(data, &rules); err != nil {
			// skip non-rule YAMLs (like configs)
			return nil
		}

		// ✅ Compile regex for each rule
		for i := range rules {
			if rules[i].Regex != "" {
				rules[i].Compiled, _ = regexp.Compile(rules[i].Regex)
			}
		}

		AllRules = append(AllRules, rules...)
		fmt.Printf("📜 Loaded %d rules from %s\n", len(rules), path)
		return nil
	})
}
