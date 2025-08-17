package utils

import "github.com/dlclark/regexp2"

// MatchRegex using regexp2 (PCRE-like, supports lookahead, atomic groups, etc.)
func MatchRegex(pattern, input string) bool {
	re := regexp2.MustCompile(pattern, regexp2.IgnoreCase|regexp2.Multiline)
	match, _ := re.MatchString(input)
	return match
}
