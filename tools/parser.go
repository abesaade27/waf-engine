/*
Core Rule Set (CRS) Parser for WAF

This program parses ModSecurity CRS `.conf` files and converts them
into YAML files compatible with the custom Go WAF.

Key components:

1. Rule struct:
  - Represents a single CRS rule after parsing.
  - Fields: ID, Name, Variable (target), Regex pattern, Phase, Severity, Block flag.

2. Main parsing logic:
  - Walks through all `.conf` files in `coreruleset/rules`.
  - Detects category based on filename (e.g., XSS, SQLi, RCE, LFI, RFI, Protocol).
  - Merges multi-line rules ending with backslashes.
  - Ignores comments and meta/control rules (TX variables, numeric operators like @lt/@gt/@eq).

3. parseActions():
  - Extracts the ID, message, phase, severity, and block/deny actions from the rule actions string.

4. flattenJSON() is not in this file but used in WAF inspection for JSON body processing.

5. saveYAML() and saveYAMLWithSpacing():
  - Convert parsed rules into YAML files.
  - `saveYAMLWithSpacing` writes the rules for a category to a file with indentation.
  - `ruleset_config.yaml` contains a list of all generated rule files for loading.

6. Output:
  - Generates YAML files in `parsed_rules` directory.
  - Allows the Go WAF to load CRS rules in a structured YAML format instead of parsing raw `.conf` at runtime.

Usage:
- Run this parser once after downloading CRS.
- The WAF then loads the generated YAML files for rule matching.
*/
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

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

func main() {
	crsPath := "coreruleset/rules" // adjust if needed
	outputDir := "parsed_rules"

	os.MkdirAll(outputDir, os.ModePerm)

	categoryRules := make(map[string][]Rule)
	secRuleRegex := regexp.MustCompile(`(?i)^SecRule\s+(\S+)\s+"([^"]+)"\s+"([^"]+)"`)

	filepath.Walk(crsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(info.Name(), ".conf") {
			return nil
		}

		category := detectCategory(info.Name())

		file, _ := os.Open(path)
		defer file.Close()
		scanner := bufio.NewScanner(file)

		var buffer string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			// Merge lines ending with backslash
			if strings.HasSuffix(line, "\\") {
				buffer += strings.TrimSuffix(line, "\\") + " "
				continue
			}
			if buffer != "" {
				line = buffer + line
				buffer = ""
			}

			// Skip comments
			if strings.HasPrefix(line, "#") || !strings.HasPrefix(strings.ToUpper(line), "SECRULE") {
				continue
			}

			matches := secRuleRegex.FindStringSubmatch(line)
			if len(matches) < 4 {
				continue
			}

			variable := matches[1]
			pattern := matches[2]
			actions := matches[3]

			// Filter out meta/control rules
			if strings.HasPrefix(variable, "TX:") {
				continue
			}
			if strings.HasPrefix(pattern, "@lt") || strings.HasPrefix(pattern, "@eq") || strings.HasPrefix(pattern, "@gt") {
				continue
			}

			rule := parseActions(variable, pattern, actions)
			categoryRules[category] = append(categoryRules[category], rule)
		}
		return nil
	})

	var config struct {
		LoadRules []string `yaml:"load_rules"`
	}

	for category, rules := range categoryRules {
		if len(rules) == 0 {
			continue
		}

		// Sort rules by numeric ID
		sort.Slice(rules, func(i, j int) bool {
			id1, _ := strconv.Atoi(rules[i].ID)
			id2, _ := strconv.Atoi(rules[j].ID)
			return id1 < id2
		})

		filename := fmt.Sprintf("rules_%s.yaml", category)
		filePath := filepath.Join(outputDir, filename)

		saveYAMLWithSpacing(filePath, rules)
		config.LoadRules = append(config.LoadRules, filename)
	}

	saveYAML(filepath.Join(outputDir, "ruleset_config.yaml"), config)

	fmt.Println("Parsing complete! Rules saved to", outputDir)
}

func detectCategory(filename string) string {
	switch {
	case strings.Contains(filename, "941"):
		return "xss"
	case strings.Contains(filename, "942"):
		return "sqli"
	case strings.Contains(filename, "930"):
		return "protocol"
	case strings.Contains(filename, "933"):
		return "rce"
	case strings.Contains(filename, "932"):
		return "lfi"
	case strings.Contains(filename, "934"):
		return "rfi"
	default:
		return "misc"
	}
}

func parseActions(variable, pattern, actions string) Rule {
	rule := Rule{
		Variable: variable,
		Regex:    pattern,
		Block:    strings.Contains(actions, "block") || strings.Contains(actions, "deny"),
	}

	for _, part := range strings.Split(actions, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "id:") {
			rule.ID = strings.TrimPrefix(part, "id:")
		}
		if strings.HasPrefix(part, "msg:") {
			rule.Name = strings.Trim(strings.TrimPrefix(part, "msg:"), "'\"")
		}
		if strings.HasPrefix(part, "phase:") {
			fmt.Sscanf(strings.TrimPrefix(part, "phase:"), "%d", &rule.Phase)
		}
		if strings.HasPrefix(strings.ToLower(part), "severity:") {
			rule.Severity = strings.TrimPrefix(part, "severity:")
		}
	}

	return rule
}

func saveYAML(path string, data interface{}) {
	file, _ := os.Create(path)
	defer file.Close()
	enc := yaml.NewEncoder(file)
	enc.SetIndent(2)
	enc.Encode(data)
}

// saveYAMLWithSpacing writes each rule with a blank line between entries
// func saveYAMLWithSpacing(path string, rules []Rule) {
// 	file, _ := os.Create(path)
// 	defer file.Close()

// 	for i, rule := range rules {
// 		enc := yaml.NewEncoder(file)
// 		enc.SetIndent(2)
// 		enc.Encode(rule)
// 		enc.Close()

// // Add a blank line after each rule except the last one
// if i < len(rules)-1 {
// 	file.WriteString("\n")
// }
// 	}
//}

func saveYAMLWithSpacing(path string, rules []Rule) {
	file, _ := os.Create(path)
	defer file.Close()

	// Encode the entire slice at once as a YAML list
	enc := yaml.NewEncoder(file)
	enc.SetIndent(2)
	enc.Encode(rules)
	enc.Close()
}
