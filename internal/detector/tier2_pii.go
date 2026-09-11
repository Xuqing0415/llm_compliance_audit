package detector

import (
	"context"

	"llm-audit-gateway/internal/types"
)

type PIIDetector struct {
	name string
}

func NewPIIDetector() *PIIDetector {
	return &PIIDetector{
		name: "pii_detector",
	}
}

func (pd *PIIDetector) Name() string {
	return pd.name
}

func (pd *PIIDetector) Tier() types.DetectionTier {
	return types.Tier2PII
}

func (pd *PIIDetector) Detect(ctx context.Context, request *types.RequestContext) (*types.DetectionResult, error) {
	return &types.DetectionResult{
		Tier:       types.Tier2PII,
		Detector:   pd.name,
		Category:   types.CategoryPII,
		Severity:   types.SeverityLow,
		Matched:    false,
		Confidence: 0,
		Action:     types.ActionAllow,
	}, nil
}

func (pd *PIIDetector) StreamDetect(ctx context.Context, chunk string, request *types.RequestContext) (*types.DetectionResult, error) {
	return &types.DetectionResult{
		Tier:       types.Tier2PII,
		Detector:   pd.name,
		Category:   types.CategoryPII,
		Severity:   types.SeverityLow,
		Matched:    false,
		Confidence: 0,
		Action:     types.ActionAllow,
	}, nil
}
