package rules

import (
	"html"
	"net/url"
	"strings"
)

type Transaction struct {
	CriticalAnomalyScore   int
	XSSScore               int
	SQLiScore              int
	InboundAnomalyScorePL1 int
	MatchedVarName         string
	MatchedVar             string
	Block                  bool
}

func (tx *Transaction) CalculateCriticalScore() {
	tx.CriticalAnomalyScore = tx.XSSScore + tx.SQLiScore
}

func DecodeInput(input string) string {
	decoded, _ := url.QueryUnescape(input)
	decoded = html.UnescapeString(decoded)
	decoded = strings.ReplaceAll(decoded, "\x00", "")
	return decoded
}
