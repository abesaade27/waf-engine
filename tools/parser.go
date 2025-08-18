package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	ID         string   `yaml:"id"`
	Name       string   `yaml:"name"`
	Variable   string   `yaml:"variable"`
	Regex      string   `yaml:"regex"`
	Phase      int      `yaml:"phase"`
	Severity   string   `yaml:"severity"`
	Block      bool     `yaml:"block"`
	Transforms []string `yaml:"transforms,omitempty"`
	Tags       []string `yaml:"tags,omitempty"`
	Paranoia   int      `yaml:"paranoia_level,omitempty"`
	Controls   []string `yaml:"controls,omitempty"`
	Chain      []Rule   `yaml:"chain,omitempty"`
}

func main() {
	crsPath := "OWASP_crs_rules"
	outDir := "parsed_rules"
	_ = os.MkdirAll(outDir, 0o755)

	catRules := make(map[string][]Rule)
	secRule := regexp.MustCompile(`(?i)^SecRule\s+(\S+)\s+"([^"]+)"\s+"([^"]+)"`)

	filepath.Walk(crsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".conf") {
			return nil
		}
		category := detectCategory(info.Name())

		f, _ := os.Open(path)
		defer f.Close()
		sc := bufio.NewScanner(f)
		var buf string
		var lastRule *Rule

		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasSuffix(line, "\\") {
				buf += strings.TrimSuffix(line, "\\") + " "
				continue
			}
			if buf != "" {
				line = buf + line
				buf = ""
			}
			if line == "" || strings.HasPrefix(line, "#") || !strings.HasPrefix(strings.ToUpper(line), "SECRULE") {
				continue
			}

			m := secRule.FindStringSubmatch(line)
			if len(m) < 4 {
				continue
			}
			variable := m[1]
			pattern := m[2]
			actions := m[3]

			// Filter meta/control rules
			if strings.HasPrefix(strings.ToUpper(variable), "TX:") {
				continue
			}
			if strings.HasPrefix(pattern, "@lt") || strings.HasPrefix(pattern, "@eq") || strings.HasPrefix(pattern, "@gt") {
				continue
			}

			r := parseActions(variable, normalizeOperator(pattern), actions)
			if r.Regex == "" {
				continue
			}

			// Handle chain
			if strings.Contains(actions, "chain") {
				if lastRule == nil {
					// Start of new chain
					catRules[category] = append(catRules[category], r)
					lastRule = &catRules[category][len(catRules[category])-1]
				} else {
					// Continuation of existing chain
					lastRule.Chain = append(lastRule.Chain, r)
					lastRule = &lastRule.Chain[len(lastRule.Chain)-1]
				}
			} else if lastRule != nil {
				// Final chain link
				lastRule.Chain = append(lastRule.Chain, r)
				lastRule = nil
			} else {
				// Normal rule
				catRules[category] = append(catRules[category], r)
			}
		}
		return nil
	})

	// Save per-category rules
	var cfg struct {
		LoadRules []string `yaml:"load_rules"`
	}
	for cat, list := range catRules {
		if len(list) == 0 {
			continue
		}
		fn := fmt.Sprintf("rules_%s.yaml", cat)
		fp := filepath.Join(outDir, fn)
		saveYAML(fp, list)
		cfg.LoadRules = append(cfg.LoadRules, fn)
	}
	saveYAML(filepath.Join(outDir, "ruleset_config.yaml"), cfg)
	fmt.Println("Parsing complete! Rules saved to", outDir)
}

// --- Helpers ---

func normalizeOperator(pattern string) string {
	switch {
	case strings.HasPrefix(pattern, "@rx "):
		return strings.TrimPrefix(pattern, "@rx ")
	case strings.HasPrefix(pattern, "@pm "):
		words := strings.Fields(strings.TrimPrefix(pattern, "@pm "))
		if len(words) == 0 {
			return ""
		}
		return "(?i)(" + strings.Join(words, "|") + ")"
	case strings.HasPrefix(pattern, "@streq "):
		val := strings.TrimPrefix(pattern, "@streq ")
		return "^" + regexp.QuoteMeta(strings.TrimSpace(val)) + "$"
	case strings.HasPrefix(pattern, "@detectSQLi"):
		// basic libinjection regex approximation
		return `(?i)(union(\s+all)?\s+select|select.+from|insert\s+into|drop\s+table|update.+set|or\s+1=1)`
	case strings.HasPrefix(pattern, "@detectXSS"):
		return `(?i)(<script|onerror\s*=|onload\s*=|javascript:|alert\s*\()`
	default:
		// Some CRS rules put plain regex without @rx
		return pattern
	}
}

func detectCategory(filename string) string {
	switch {
	case strings.Contains(filename, "901"):
		return "initialization"
	case strings.Contains(filename, "905"):
		return "common_exceptions"
	case strings.Contains(filename, "911"):
		return "method_inforcement"
	case strings.Contains(filename, "913"):
		return "scanner_detection"
	case strings.Contains(filename, "920"):
		return "protocol_inforcement"
	case strings.Contains(filename, "921"):
		return "protocol_attack"
	case strings.Contains(filename, "922"):
		return "multipart_attack"
	case strings.Contains(filename, "930"):
		return "rfi"
	case strings.Contains(filename, "931"):
		return "lfi"
	case strings.Contains(filename, "932"):
		return "rce"
	case strings.Contains(filename, "933"):
		return "php"
	case strings.Contains(filename, "934"):
		return "generic_attack"
	case strings.Contains(filename, "941"):
		return "xss"
	case strings.Contains(filename, "942"):
		return "sqli"
	case strings.Contains(filename, "943"):
		return "session_fixation"
	case strings.Contains(filename, "944"):
		return "java"
	case strings.Contains(filename, "959"):
		return "blocking_evaluation"
	case strings.Contains(filename, "980"):
		return "correlation"
	default:
		return "misc"
	}
}

func parseActions(variable, pattern, actions string) Rule {
	r := Rule{
		Variable: variable,
		Regex:    pattern,
		Block:    strings.Contains(actions, "block") || strings.Contains(actions, "deny"),
	}
	for _, part := range strings.Split(actions, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "id:"):
			r.ID = strings.TrimPrefix(part, "id:")
		case strings.HasPrefix(part, "msg:"):
			r.Name = strings.Trim(strings.TrimPrefix(part, "msg:"), "'\"")
		case strings.HasPrefix(part, "phase:"):
			fmt.Sscanf(strings.TrimPrefix(part, "phase:"), "%d", &r.Phase)
		case strings.HasPrefix(strings.ToLower(part), "severity:"):
			r.Severity = strings.TrimPrefix(part, "severity:")
		case strings.HasPrefix(part, "t:"):
			r.Transforms = append(r.Transforms, strings.TrimPrefix(part, "t:"))
		case strings.HasPrefix(part, "tag:"):
			tag := strings.Trim(strings.TrimPrefix(part, "tag:"), "'\"")
			r.Tags = append(r.Tags, tag)
		case strings.HasPrefix(part, "paranoia-level:"):
			if lvl, err := strconv.Atoi(strings.TrimPrefix(part, "paranoia-level:")); err == nil {
				r.Paranoia = lvl
			}
		case strings.HasPrefix(part, "ctl:"):
			r.Controls = append(r.Controls, strings.TrimPrefix(part, "ctl:"))
		}
	}
	return r
}

func saveYAML(path string, data any) {
	f, _ := os.Create(path)
	defer f.Close()
	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	_ = enc.Encode(data)
}
