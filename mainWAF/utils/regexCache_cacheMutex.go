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
