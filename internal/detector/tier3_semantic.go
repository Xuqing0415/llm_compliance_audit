package detector

import (
	"context"

	"llm-audit-gateway/internal/types"
)

type SemanticDetector struct {
	name string
}

func NewSemanticDetector() *SemanticDetector {
	return &SemanticDetector{
		name: "semantic_detector",
	}
}

func (sd *SemanticDetector) Name() string {
	return sd.name
}

func (sd *SemanticDetector) Tier() types.DetectionTier {
	return types.Tier3Semantic
}

func (sd *SemanticDetector) Detect(ctx context.Context, request *types.RequestContext) (*types.DetectionResult, error) {
	return &types.DetectionResult{
		Tier:       types.Tier3Semantic,
		Detector:   sd.name,
		Category:   types.CategoryPromptInjection,
		Severity:   types.SeverityLow,
		Matched:    false,
		Confidence: 0,
		Action:     types.ActionAllow,
	}, nil
}

func (sd *SemanticDetector) StreamDetect(ctx context.Context, chunk string, request *types.RequestContext) (*types.DetectionResult, error) {
	return &types.DetectionResult{
		Tier:       types.Tier3Semantic,
		Detector:   sd.name,
		Category:   types.CategoryPromptInjection,
		Severity:   types.SeverityLow,
		Matched:    false,
		Confidence: 0,
		Action:     types.ActionAllow,
	}, nil
}
