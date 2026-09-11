package types

import "time"

type Action string

const (
	ActionAllow                  Action = "ALLOW"
	ActionBlock                  Action = "BLOCK"
	ActionAlert                  Action = "ALERT"
	ActionRedact                 Action = "REDACT"
	ActionReplace                Action = "REPLACE"
	ActionPassThroughWithWarning Action = "PASS_THROUGH_WITH_WARNING"
)

type DetectionTier string

const (
	Tier1Regex    DetectionTier = "TIER1_REGEX"
	Tier2PII      DetectionTier = "TIER2_PII"
	Tier3Semantic DetectionTier = "TIER3_SEMANTIC"
)

type DetectionSeverity string

const (
	SeverityLow      DetectionSeverity = "LOW"
	SeverityMedium   DetectionSeverity = "MEDIUM"
	SeverityHigh     DetectionSeverity = "HIGH"
	SeverityCritical DetectionSeverity = "CRITICAL"
)

type DetectionCategory string

const (
	CategorySensitiveData   DetectionCategory = "SENSITIVE_DATA"
	CategoryPII             DetectionCategory = "PII"
	CategoryPromptInjection DetectionCategory = "PROMPT_INJECTION"
	CategoryMalicious       DetectionCategory = "MALICIOUS"
	CategoryCompliance      DetectionCategory = "COMPLIANCE"
	CategoryOther           DetectionCategory = "OTHER"
)

type DetectionResult struct {
	Tier         DetectionTier     `json:"tier"`
	Detector     string            `json:"detector"`
	Category     DetectionCategory `json:"category"`
	Severity     DetectionSeverity `json:"severity"`
	Matched      bool              `json:"matched"`
	MatchDetail  string            `json:"match_detail,omitempty"`
	Confidence   float64           `json:"confidence"`
	Action       Action            `json:"action"`
	Message      string            `json:"message,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
	HitRuleID    string            `json:"hit_rule_id,omitempty"`
	MatchedText  string            `json:"matched_text,omitempty"`
	ForceExecute bool              `json:"force_execute,omitempty"`
}

func NewDetectionResult(tier DetectionTier, detector string) *DetectionResult {
	return &DetectionResult{
		Tier:      tier,
		Detector:  detector,
		Timestamp: time.Now(),
	}
}

type ExecutionPolicyMode string

const (
	PolicyModeDefault    ExecutionPolicyMode = "default"
	PolicyModeForceBlock ExecutionPolicyMode = "force_block"
	PolicyModeForceAudit ExecutionPolicyMode = "force_audit"
)

type ExecutionPolicy struct {
	Name         string              `yaml:"name"`
	HeaderKey    string              `yaml:"header_key"`
	HeaderValues []string            `yaml:"header_values"`
	Mode         ExecutionPolicyMode `yaml:"mode"`
	Priority     int                 `yaml:"priority"`
}
