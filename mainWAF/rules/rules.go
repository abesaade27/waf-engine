package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Rule defines a single WAF rule structure
type Rule struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Variable string `yaml:"variable"`
	Regex    string `yaml:"regex"`
	Phase    int    `yaml:"phase"`
	Severity string `yaml:"severity"`
	Block    bool   `yaml:"block"`
	Compiled *regexp.Regexp
}

// AllRules holds every rule loaded from YAML
var AllRules []Rule

// LoadRules walks through a directory and loads all YAML rule files
func LoadRules(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		var rules []Rule
		dec := yaml.NewDecoder(f)
		if err := dec.Decode(&rules); err != nil {
			// skip files that aren’t lists of rules (like ruleset_config.yaml)
			return nil
		}

		// ✅ Compile regex immediately for each rule
		for i := range rules {
			if rules[i].Regex != "" {
				rules[i].Compiled, _ = regexp.Compile(rules[i].Regex)
			}
		}

		AllRules = append(AllRules, rules...)
		fmt.Printf("Loaded %d rules from %s\n", len(rules), path)
		return nil
	})
}
