package detector

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/goccy/go-yaml"
	"github.com/sirupsen/logrus"
)

type ExemptionRule struct {
	RuleName string   `yaml:"rule_name"`
	Keywords []string `yaml:"keywords"`
}

type FalsePositivePattern struct {
	RuleName string   `yaml:"rule_name"`
	Patterns []string `yaml:"patterns"`
}

type ExemptionConfig struct {
	Exemptions     []ExemptionRule        `yaml:"exemptions"`
	FalsePositives []FalsePositivePattern `yaml:"false_positives"`
}

type ExemptionManager struct {
	mu             sync.RWMutex
	exemptions     map[string][]string
	falsePositives map[string][]*regexp.Regexp
	ruleNames      map[string]string
	sourceFile     string
}

func NewExemptionManager() *ExemptionManager {
	return &ExemptionManager{
		exemptions:     make(map[string][]string),
		falsePositives: make(map[string][]*regexp.Regexp),
		ruleNames:      make(map[string]string),
	}
}

func (em *ExemptionManager) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var config ExemptionConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return err
	}

	em.mu.Lock()
	defer em.mu.Unlock()

	em.exemptions = make(map[string][]string)
	em.ruleNames = make(map[string]string)
	for _, rule := range config.Exemptions {
		key := strings.ToLower(rule.RuleName)
		em.exemptions[key] = rule.Keywords
		em.ruleNames[key] = rule.RuleName
	}

	em.falsePositives = make(map[string][]*regexp.Regexp)
	for _, fp := range config.FalsePositives {
		patterns := make([]*regexp.Regexp, 0)
		for _, pattern := range fp.Patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				logrus.Warn("Invalid false positive pattern:", pattern, err)
				continue
			}
			patterns = append(patterns, re)
		}
		key := strings.ToLower(fp.RuleName)
		em.falsePositives[key] = patterns
		if _, ok := em.ruleNames[key]; !ok {
			em.ruleNames[key] = fp.RuleName
		}
	}

	em.sourceFile = path

	logrus.Info("Loaded exemption rules: ", len(em.exemptions), ", false positive patterns: ", len(em.falsePositives))
	return nil
}

func (em *ExemptionManager) IsExempt(ruleName, content string) bool {
	em.mu.RLock()
	defer em.mu.RUnlock()

	keywords, ok := em.exemptions[strings.ToLower(ruleName)]
	if !ok {
		return false
	}

	for _, keyword := range keywords {
		if strings.Contains(strings.ToLower(content), strings.ToLower(keyword)) {
			return true
		}
	}

	return false
}

func (em *ExemptionManager) IsFalsePositive(ruleName, matchedText string) bool {
	em.mu.RLock()
	defer em.mu.RUnlock()

	patterns, ok := em.falsePositives[strings.ToLower(ruleName)]
	if !ok {
		return false
	}

	for _, pattern := range patterns {
		if pattern.MatchString(matchedText) {
			return true
		}
	}

	return false
}

func (em *ExemptionManager) AddKeyword(ruleName, keyword string) {
	em.mu.Lock()
	defer em.mu.Unlock()

	key := strings.ToLower(ruleName)
	if _, ok := em.ruleNames[key]; !ok {
		em.ruleNames[key] = ruleName
	}
	if _, ok := em.exemptions[key]; !ok {
		em.exemptions[key] = make([]string, 0)
	}

	for _, k := range em.exemptions[key] {
		if strings.EqualFold(k, keyword) {
			return
		}
	}

	em.exemptions[key] = append(em.exemptions[key], keyword)
	logrus.Info("Added keyword '", keyword, "' to rule '", ruleName, "'")
}

func (em *ExemptionManager) RemoveKeyword(ruleName, keyword string) {
	em.mu.Lock()
	defer em.mu.Unlock()

	key := strings.ToLower(ruleName)
	keywords, ok := em.exemptions[key]
	if !ok {
		return
	}

	for i, k := range keywords {
		if strings.EqualFold(k, keyword) {
			em.exemptions[key] = append(keywords[:i], keywords[i+1:]...)
			logrus.Info("Removed keyword '", keyword, "' from rule '", ruleName, "'")
			return
		}
	}
}

func (em *ExemptionManager) AddFalsePositive(ruleName, pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	em.mu.Lock()
	defer em.mu.Unlock()

	key := strings.ToLower(ruleName)
	if _, ok := em.ruleNames[key]; !ok {
		em.ruleNames[key] = ruleName
	}
	if _, ok := em.falsePositives[key]; !ok {
		em.falsePositives[key] = make([]*regexp.Regexp, 0)
	}

	em.falsePositives[key] = append(em.falsePositives[key], re)
	logrus.Info("Added false positive pattern '", pattern, "' to rule '", ruleName, "'")
	return nil
}

func (em *ExemptionManager) SetSourceFile(path string) {
	em.mu.Lock()
	defer em.mu.Unlock()
	em.sourceFile = path
}

func (em *ExemptionManager) SourceFile() string {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return em.sourceFile
}

// Persist writes the current in-memory exemptions/false-positives back to the
// source YAML file so admin-created allowlists survive config reloads.
func (em *ExemptionManager) Persist() error {
	em.mu.RLock()
	path := em.sourceFile
	if path == "" {
		em.mu.RUnlock()
		return os.ErrNotExist
	}

	cfg := ExemptionConfig{}
	exemptionNames := make([]string, 0, len(em.exemptions))
	for name := range em.exemptions {
		exemptionNames = append(exemptionNames, name)
	}
	sort.Strings(exemptionNames)
	for _, name := range exemptionNames {
		display := em.ruleNames[name]
		if display == "" {
			display = name
		}
		cfg.Exemptions = append(cfg.Exemptions, ExemptionRule{
			RuleName: display,
			Keywords: append([]string(nil), em.exemptions[name]...),
		})
	}

	fpNames := make([]string, 0, len(em.falsePositives))
	for name := range em.falsePositives {
		fpNames = append(fpNames, name)
	}
	sort.Strings(fpNames)
	for _, name := range fpNames {
		display := em.ruleNames[name]
		if display == "" {
			display = name
		}
		patterns := make([]string, 0, len(em.falsePositives[name]))
		for _, re := range em.falsePositives[name] {
			patterns = append(patterns, re.String())
		}
		cfg.FalsePositives = append(cfg.FalsePositives, FalsePositivePattern{
			RuleName: display,
			Patterns: patterns,
		})
	}
	em.mu.RUnlock()

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (em *ExemptionManager) GetAllExemptions() map[string][]string {
	em.mu.RLock()
	defer em.mu.RUnlock()

	result := make(map[string][]string)
	for k, v := range em.exemptions {
		result[k] = make([]string, len(v))
		copy(result[k], v)
	}

	return result
}

func (em *ExemptionManager) GetAllFalsePositives() map[string][]string {
	em.mu.RLock()
	defer em.mu.RUnlock()

	result := make(map[string][]string)
	for k, v := range em.falsePositives {
		patterns := make([]string, 0, len(v))
		for _, re := range v {
			patterns = append(patterns, re.String())
		}
		result[k] = patterns
	}

	return result
}
