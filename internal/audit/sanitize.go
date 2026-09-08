package audit

import (
	"regexp"
	"strings"

	"llm-audit-gateway/internal/types"
)

var (
	idCardPattern   = regexp.MustCompile(`[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]`)
	phonePattern    = regexp.MustCompile(`1[3-9]\d{9}`)
	bankCardPattern = regexp.MustCompile(`\b\d{16,19}\b`)
	emailPattern    = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
)

// maskToken partially masks a sensitive token. It keeps a small prefix/suffix
// for readability while removing the value that could be used as plaintext PII.
func maskToken(s string) string {
	runes := []rune(s)
	n := len(runes)
	if n <= 6 {
		return strings.Repeat("*", n)
	}
	keep := 3
	if n <= 12 {
		keep = 2
	}
	return string(runes[:keep]) + strings.Repeat("*", n-keep-3) + string(runes[n-3:])
}

func maskEmail(s string) string {
	at := strings.LastIndex(s, "@")
	if at <= 0 {
		return maskToken(s)
	}
	return maskToken(s[:at]) + s[at:]
}

// sanitizeSensitive scrubs known sensitive values out of free-text content so
// audit logs never persist raw ID card numbers, phone numbers, bank cards or
// email addresses.
func sanitizeSensitive(s string) string {
	if s == "" {
		return ""
	}
	s = idCardPattern.ReplaceAllStringFunc(s, maskToken)
	s = bankCardPattern.ReplaceAllStringFunc(s, maskToken)
	s = phonePattern.ReplaceAllStringFunc(s, maskToken)
	s = emailPattern.ReplaceAllStringFunc(s, maskEmail)
	return s
}

// sanitizeDetectionResults returns a copy of the results with the raw matched
// text removed from persistence-bound copies.
func sanitizeDetectionResults(in []types.DetectionResult) []types.DetectionResult {
	if len(in) == 0 {
		return nil
	}
	out := make([]types.DetectionResult, len(in))
	for i, r := range in {
		r.MatchedText = sanitizeSensitive(r.MatchedText)
		r.MatchDetail = sanitizeSensitive(r.MatchDetail)
		out[i] = r
	}
	return out
}

// safeBody bounds and sanitizes a request/response body for persistence while
// returning the SHA-256 of the original (full) content for integrity checking.
func safeBody(raw string) (stored string, rawHash string) {
	if raw == "" {
		return "", ""
	}
	rawHash = computeSHA256(raw)
	runes := []rune(raw)
	const maxPersistedRunes = 4096
	if len(runes) > maxPersistedRunes {
		raw = string(runes[:maxPersistedRunes]) + "[truncated]"
	}
	return sanitizeSensitive(raw), rawHash
}

func sanitizeChunks(chunks []string) []string {
	if len(chunks) == 0 {
		return nil
	}
	out := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		out = append(out, sanitizeSensitive(chunk))
	}
	return out
}
