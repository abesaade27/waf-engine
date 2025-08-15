/*
Regex Cache Utilities for WAF

This package provides functions to efficiently handle regular expression matching
with caching, improving performance when repeatedly checking request values against
WAF rules.

Key Components:

1. regexCache
  - In-memory map to store compiled regular expressions.
  - Key: regex pattern string
  - Value: compiled *regexp.Regexp

2. cacheMutex
  - RWMutex to safely handle concurrent reads/writes to the regexCache.

3. MatchRegex(pattern, value string) bool
  - Checks if the given value matches the regex pattern.
  - If the pattern is not already compiled, compiles it and stores it in regexCache.
  - Uses read-lock for fast lookups and write-lock only when inserting a new compiled regex.
  - Returns true if the value matches the pattern, false otherwise.
  - Prevents repeated compilation overhead for frequently used WAF rules.

4. ClearRegexCache()
  - Clears all entries in the regexCache.
  - Useful when reloading rules to avoid using stale compiled patterns.
  - Acquires write-lock to safely replace the map.

Usage:
- Call MatchRegex(pattern, value) instead of regexp.MatchString directly for better performance.
- Call ClearRegexCache() whenever you reload YAML rules to ensure fresh regex compilation.
*/
package utils

import (
	"regexp"
	"sync"
)

var (
	regexCache = make(map[string]*regexp.Regexp)
	cacheMutex sync.RWMutex
)

func MatchRegex(pattern, value string) bool {
	cacheMutex.RLock()
	re, exists := regexCache[pattern]
	cacheMutex.RUnlock()

	if !exists {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}

		cacheMutex.Lock()
		regexCache[pattern] = compiled
		cacheMutex.Unlock()
		re = compiled
	}

	return re.MatchString(value)
}

func ClearRegexCache() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	regexCache = make(map[string]*regexp.Regexp)
}
