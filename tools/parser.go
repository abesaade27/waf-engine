package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	crsPath := "crs/rules" // adjust if needed
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
		filename := fmt.Sprintf("rules_%s.yaml", category)
		filePath := filepath.Join(outputDir, filename)

		saveYAML(filePath, rules)
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
