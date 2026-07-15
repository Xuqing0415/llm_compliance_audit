package detector

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"llm-audit-gateway/internal/config"
	"llm-audit-gateway/internal/types"
)

type RegexDetector struct {
	name                  string
	rules                 []compiledRule
	exemptionManager      *ExemptionManager
	fingerprintRules      []fingerprintRule
	disabledRules         map[string]bool
	purposeActionOverrides map[string]map[string]types.Action
	mu                    sync.RWMutex
}

type compiledRule struct {
	name          string
	pattern       *regexp.Regexp
	category      types.DetectionCategory
	severity      types.DetectionSeverity
	action        types.Action
	description   string
	validator     func(string) bool
}

type fingerprintRule struct {
	name        string
	patterns    []*regexp.Regexp
	category    types.DetectionCategory
	severity    types.DetectionSeverity
	description string
}

func NewRegexDetector(cfg *config.Config, em *ExemptionManager) (*RegexDetector, error) {
	if em == nil {
		em = NewExemptionManager()
	}

	detector := &RegexDetector{
		name:                  "regex_detector",
		rules:                 make([]compiledRule, 0),
		exemptionManager:      em,
		fingerprintRules: []fingerprintRule{
			{
				name:        "IgnorePreviousInstructions",
				patterns:    []*regexp.Regexp{regexp.MustCompile(`(?i)ignore\s+previous\s+instructions?`), regexp.MustCompile(`(?i)forget\s+everything\s+above`)},
				category:    types.CategoryPromptInjection,
				severity:    types.SeverityCritical,
				description: "对抗性提示词：忽略前置指令",
			},
			{
				name:        "OutputSystemPrompt",
				patterns:    []*regexp.Regexp{regexp.MustCompile(`(?i)output\s+your\s+system\s+prompt`), regexp.MustCompile(`(?i)show\s+me\s+your\s+instructions`)},
				category:    types.CategoryPromptInjection,
				severity:    types.SeverityCritical,
				description: "对抗性提示词：输出系统提示词",
			},
			{
				name:        "RolePlayBypass",
				patterns:    []*regexp.Regexp{regexp.MustCompile(`(?i)roleplay\s+as\s+a`), regexp.MustCompile(`(?i)act\s+as\s+(?:hacker|cracker|attacker)`)},
				category:    types.CategoryPromptInjection,
				severity:    types.SeverityHigh,
				description: "对抗性提示词：角色扮演绕过",
			},
			{
				name:        "MaliciousTask",
				patterns:    []*regexp.Regexp{regexp.MustCompile(`(?i)how\s+to\s+(?:hack|crack|steal|phish|ddos)`), regexp.MustCompile(`(?i)write\s+a\s+(?:virus|malware|ransomware)`)},
				category:    types.CategoryMalicious,
				severity:    types.SeverityCritical,
				description: "恶意任务请求",
			},
		},
		disabledRules:         make(map[string]bool),
		purposeActionOverrides: make(map[string]map[string]types.Action),
	}

	if err := detector.loadRules(cfg); err != nil {
		return nil, err
	}

	return detector, nil
}

func (rd *RegexDetector) Name() string {
	return rd.name
}

func (rd *RegexDetector) Tier() types.DetectionTier {
	return types.Tier1Regex
}

func (rd *RegexDetector) ToggleRule(ruleName string, enable bool) {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	if enable {
		delete(rd.disabledRules, ruleName)
		logrus.Info("Enabled rule: ", ruleName)
	} else {
		rd.disabledRules[ruleName] = true
		logrus.Info("Disabled rule: ", ruleName)
	}
}

func (rd *RegexDetector) isRuleDisabled(ruleName string) bool {
	rd.mu.RLock()
	defer rd.mu.RUnlock()

	return rd.disabledRules[ruleName]
}

func (rd *RegexDetector) SetPurposeActionOverride(purpose, ruleName string, action types.Action) {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	if _, ok := rd.purposeActionOverrides[purpose]; !ok {
		rd.purposeActionOverrides[purpose] = make(map[string]types.Action)
	}
	rd.purposeActionOverrides[purpose][ruleName] = action
	logrus.Info("Set purpose action override: purpose=", purpose, ", rule=", ruleName, ", action=", action)
}

func (rd *RegexDetector) GetPurposeActionOverride(purpose, ruleName string) (types.Action, bool) {
	rd.mu.RLock()
	defer rd.mu.RUnlock()

	if purposeMap, ok := rd.purposeActionOverrides[purpose]; ok {
		if action, ok := purposeMap[ruleName]; ok {
			return action, true
		}
	}
	return types.ActionAllow, false
}

func (rd *RegexDetector) InitDefaultPurposeOverrides() {
	rd.SetPurposeActionOverride("export", "身份证号", types.ActionAlert)
	rd.SetPurposeActionOverride("export", "银行卡号", types.ActionAlert)
	rd.SetPurposeActionOverride("export", "手机号", types.ActionAlert)
	rd.SetPurposeActionOverride("export", "邮箱", types.ActionAlert)

	rd.SetPurposeActionOverride("codegen", "命令注入", types.ActionBlock)
	rd.SetPurposeActionOverride("codegen", "SQL注入", types.ActionBlock)
	rd.SetPurposeActionOverride("codegen", "手机号", types.ActionAlert)
	rd.SetPurposeActionOverride("codegen", "邮箱", types.ActionAlert)
}

func validateIDCard(id string) bool {
	if len(id) != 18 {
		return false
	}

	weight := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	checkCode := []byte{'1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'}

	sum := 0
	for i := 0; i < 17; i++ {
		digit, err := strconv.Atoi(string(id[i]))
		if err != nil {
			return false
		}
		sum += digit * weight[i]
	}

	remainder := sum % 11
	expected := checkCode[remainder]
	actual := id[17]

	return expected == actual || (expected == 'X' && actual == 'x')
}

func validateBankCard(card string) bool {
	card = strings.ReplaceAll(card, " ", "")
	if len(card) < 16 || len(card) > 19 {
		return false
	}

	sum := 0
	alternate := false
	for i := len(card) - 1; i >= 0; i-- {
		digit, err := strconv.Atoi(string(card[i]))
		if err != nil {
			return false
		}

		if alternate {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}

		sum += digit
		alternate = !alternate
	}

	return sum%10 == 0
}

func validatePhone(phone string) bool {
	if len(phone) != 11 {
		return false
	}

	prefixes := []string{"13", "14", "15", "16", "17", "18", "19"}
	prefix := phone[:2]

	for _, p := range prefixes {
		if prefix == p {
			return true
		}
	}

	return false
}

func (rd *RegexDetector) loadRules(cfg *config.Config) error {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	rd.rules = make([]compiledRule, 0)

	rulesConfig := []struct {
		name        string
		pattern     string
		category    string
		severity    string
		action      string
		description string
		validator   func(string) bool
	}{
		{
			name:        "身份证号",
			pattern:     "[1-9]\\d{5}(18|19|20)\\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\\d|3[01])\\d{3}[\\dXx]",
			category:    "SENSITIVE_DATA",
			severity:    "HIGH",
			action:      "BLOCK",
			description: "中国身份证号",
			validator:   validateIDCard,
		},
		{
			name:        "手机号",
			pattern:     "1[3-9]\\d{9}",
			category:    "SENSITIVE_DATA",
			severity:    "MEDIUM",
			action:      "BLOCK",
			description: "中国手机号",
			validator:   validatePhone,
		},
		{
			name:        "邮箱",
			pattern:     "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
			category:    "SENSITIVE_DATA",
			severity:    "MEDIUM",
			action:      "BLOCK",
			description: "邮箱地址",
			validator:   nil,
		},
		{
			name:        "银行卡号",
			pattern:     "\\b\\d{16,19}\\b",
			category:    "SENSITIVE_DATA",
			severity:    "HIGH",
			action:      "BLOCK",
			description: "银行卡号",
			validator:   validateBankCard,
		},
		{
			name:        "IP地址",
			pattern:     "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b",
			category:    "OTHER",
			severity:    "LOW",
			action:      "ALERT",
			description: "IPv4地址",
			validator:   nil,
		},
		{
			name:        "URL",
			pattern:     "https?://[\\w\\-._~:/?#[\\]@!$&'()*+,;=%]+",
			category:    "OTHER",
			severity:    "LOW",
			action:      "ALERT",
			description: "URL地址",
			validator:   nil,
		},
		{
			name:        "命令注入",
			pattern:     "(?:;|\\|\\||&&|\\$\\(|`|\\b(?:cat|ls|rm|mkdir|chmod|wget|curl|nc)\\b)",
			category:    "MALICIOUS",
			severity:    "CRITICAL",
			action:      "BLOCK",
			description: "命令注入检测",
			validator:   nil,
		},
		{
			name:        "SQL注入",
			pattern:     "(?:(?:')(?:AND|OR)\\s+\\d+=\\d+|UNION\\s+SELECT|DROP\\s+TABLE|INSERT\\s+INTO)",
			category:    "MALICIOUS",
			severity:    "CRITICAL",
			action:      "BLOCK",
			description: "SQL注入检测",
			validator:   nil,
		},
	}

	for _, rule := range rulesConfig {
		pattern, err := regexp.Compile(rule.pattern)
		if err != nil {
			logrus.Warn("Invalid regex pattern:", rule.name, err)
			continue
		}

		rd.rules = append(rd.rules, compiledRule{
			name:        rule.name,
			pattern:     pattern,
			category:    types.DetectionCategory(rule.category),
			severity:    types.DetectionSeverity(rule.severity),
			action:      types.Action(rule.action),
			description: rule.description,
			validator:   rule.validator,
		})
	}

	logrus.Info("Loaded ", len(rd.rules), " regex rules")
	return nil
}

func (rd *RegexDetector) ReloadRules(cfg *config.Config) error {
	return rd.loadRules(cfg)
}

func (rd *RegexDetector) Detect(ctx context.Context, request *types.RequestContext) (*types.DetectionResult, error) {
	rd.mu.RLock()
	rules := make([]compiledRule, len(rd.rules))
	copy(rules, rd.rules)
	fingerprints := make([]fingerprintRule, len(rd.fingerprintRules))
	copy(fingerprints, rd.fingerprintRules)
	rd.mu.RUnlock()

	if len(rules) == 0 && len(fingerprints) == 0 {
		return &types.DetectionResult{
			Tier:      types.Tier1Regex,
			Detector:  rd.name,
			Category:  types.CategoryOther,
			Severity:  types.SeverityLow,
			Matched:   false,
			Confidence: 0,
			Action:    types.ActionAllow,
		}, nil
	}

	content := request.RequestBody

	for _, rule := range rules {
		if rd.isRuleDisabled(rule.name) {
			continue
		}

		if rd.exemptionManager != nil && rd.exemptionManager.IsExempt(rule.name, content) {
			continue
		}

		if rule.pattern.MatchString(content) {
			matches := rule.pattern.FindAllString(content, -1)
			validMatches := make([]string, 0)

			for _, match := range matches {
				if rule.validator == nil || rule.validator(match) {
					if rd.exemptionManager != nil && rd.exemptionManager.IsFalsePositive(rule.name, match) {
						continue
					}
					validMatches = append(validMatches, match)
				}
			}

			if len(validMatches) == 0 {
				continue
			}

			matchDetail := ""
			if len(validMatches) > 0 {
				if len(validMatches) > 3 {
					matchDetail = "[" + validMatches[0] + ", " + validMatches[1] + ", " + validMatches[2] + ", ...]"
				} else {
					matchDetail = "[" + joinStrings(validMatches, ", ") + "]"
				}
			}

			matchedText := ""
			if len(validMatches) > 0 {
				matchedText = validMatches[0]
			}

			action := rule.action

			if request.RequestPurpose != "" {
				if overrideAction, ok := rd.GetPurposeActionOverride(request.RequestPurpose, rule.name); ok {
					action = overrideAction
				}
			}

			return &types.DetectionResult{
				Tier:        types.Tier1Regex,
				Detector:    rd.name,
				Category:    rule.category,
				Severity:    rule.severity,
				Matched:     true,
				MatchDetail: matchDetail,
				Confidence:  1.0,
				Action:      action,
				Message:     rule.description + ": " + rule.name,
				HitRuleID:   rule.name,
				MatchedText: matchedText,
			}, nil
		}
	}

	for _, fp := range fingerprints {
		matchCount := 0
		for _, pattern := range fp.patterns {
			if pattern.MatchString(content) {
				matchCount++
			}
		}

		if matchCount >= len(fp.patterns) {
			return &types.DetectionResult{
				Tier:        types.Tier1Regex,
				Detector:    rd.name,
				Category:    fp.category,
				Severity:    fp.severity,
				Matched:     true,
				MatchDetail: fp.name,
				Confidence:  1.0,
				Action:      types.ActionBlock,
				Message:     fp.description,
			}, nil
		}
	}

	return &types.DetectionResult{
		Tier:      types.Tier1Regex,
		Detector:  rd.name,
		Category:  types.CategoryOther,
		Severity:  types.SeverityLow,
		Matched:   false,
		Confidence: 0,
		Action:    types.ActionAllow,
	}, nil
}

func (rd *RegexDetector) StreamDetect(ctx context.Context, chunk string, request *types.RequestContext) (*types.DetectionResult, error) {
	return rd.Detect(ctx, &types.RequestContext{
		RequestBody: chunk,
	})
}

func (rd *RegexDetector) NewStreamState() types.StreamState {
	return &regexStreamState{}
}

func (rd *RegexDetector) DetectWithState(ctx context.Context, accumulatedText string, state types.StreamState) (*types.DetectionResult, error) {
	return rd.Detect(ctx, &types.RequestContext{
		RequestBody: accumulatedText,
	})
}

type regexStreamState struct{}

func (s *regexStreamState) Reset() {}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}