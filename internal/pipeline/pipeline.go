package pipeline

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"llm-audit-gateway/internal/types"
)

type DetectionPipeline struct {
	detectors []types.Detector
	stats     *StatsCollector
	mu        sync.RWMutex
}

func NewDetectionPipeline() *DetectionPipeline {
	return &DetectionPipeline{
		detectors: make([]types.Detector, 0),
		stats:     NewStatsCollector(10000),
	}
}

func (p *DetectionPipeline) noMatchResult() *types.DetectionResult {
	return &types.DetectionResult{
		Tier:       types.Tier1Regex,
		Detector:   "pipeline",
		Category:   types.CategoryOther,
		Severity:   types.SeverityLow,
		Matched:    false,
		Confidence: 0,
		Action:     types.ActionAllow,
	}
}

func (p *DetectionPipeline) GetStats() *StatsCollector {
	return p.stats
}

func (p *DetectionPipeline) AddDetector(detector types.Detector) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.detectors = append(p.detectors, detector)
}

func (p *DetectionPipeline) RemoveDetector(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, d := range p.detectors {
		if d.Name() == name {
			p.detectors = append(p.detectors[:i], p.detectors[i+1:]...)
			break
		}
	}
}

func (p *DetectionPipeline) ClearDetectors() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.detectors = make([]types.Detector, 0)
}

func (p *DetectionPipeline) Execute(ctx context.Context, request *types.RequestContext) (*types.DetectionResult, error) {
	p.mu.RLock()
	detectors := make([]types.Detector, len(p.detectors))
	copy(detectors, p.detectors)
	p.mu.RUnlock()

	for _, detector := range detectors {
		start := time.Now()
		result, err := detector.Detect(ctx, request)
		duration := time.Since(start)

		if p.stats != nil {
			matched := result != nil && result.Matched
			p.stats.RecordLatency(detector.Name(), duration, matched)
		}

		if err != nil {
			logrus.Warn("Detector error:", detector.Name(), err)
			continue
		}

		if result != nil && result.Matched {
			return result, nil
		}
	}

	return &types.DetectionResult{
		Tier:       types.Tier1Regex,
		Detector:   "pipeline",
		Category:   types.CategoryOther,
		Severity:   types.SeverityLow,
		Matched:    false,
		Confidence: 0,
		Action:     types.ActionAllow,
	}, nil
}

func (p *DetectionPipeline) ExecuteParallel(ctx context.Context, request *types.RequestContext) (*types.DetectionResult, error) {
	p.mu.RLock()
	detectors := make([]types.Detector, len(p.detectors))
	copy(detectors, p.detectors)
	p.mu.RUnlock()

	if len(detectors) == 0 {
		return p.noMatchResult(), nil
	}

	resultChan := make(chan *types.DetectionResult, len(detectors))
	errChan := make(chan error, len(detectors))
	wg := sync.WaitGroup{}

	for _, detector := range detectors {
		wg.Add(1)
		go func(d types.Detector) {
			defer wg.Done()
			start := time.Now()
			result, err := d.Detect(ctx, request)
			duration := time.Since(start)

			if p.stats != nil {
				matched := result != nil && result.Matched
				p.stats.RecordLatency(d.Name(), duration, matched)
			}

			if err != nil {
				errChan <- err
				return
			}
			if result != nil && result.Matched {
				resultChan <- result
			}
		}(detector)
	}

	go func() {
		wg.Wait()
		close(resultChan)
		close(errChan)
	}()

	// Return on the first detector that reports a match so a slow detector no
	// longer holds up the whole request. Detectors still running when a match
	// arrives finish in the background; both channels are buffered to fit every
	// detector, so they can never block on send.
	for {
		select {
		case result, ok := <-resultChan:
			if !ok {
				// Both channels are closed together after every detector has
				// finished; no match was found.
				return p.noMatchResult(), nil
			}
			if result != nil {
				return result, nil
			}
		case err, ok := <-errChan:
			if ok && err != nil {
				logrus.Warn("Detector error:", err)
			}
		}
	}
}

func (p *DetectionPipeline) ExecuteStream(ctx context.Context, chunk string, request *types.RequestContext) (*types.DetectionResult, error) {
	p.mu.RLock()
	detectors := make([]types.Detector, len(p.detectors))
	copy(detectors, p.detectors)
	p.mu.RUnlock()

	for _, detector := range detectors {
		result, err := detector.StreamDetect(ctx, chunk, request)
		if err != nil {
			logrus.Warn("Stream detector error:", detector.Name(), err)
			continue
		}

		if result != nil && result.Matched {
			return result, nil
		}
	}

	return &types.DetectionResult{
		Tier:       types.Tier1Regex,
		Detector:   "pipeline",
		Category:   types.CategoryOther,
		Severity:   types.SeverityLow,
		Matched:    false,
		Confidence: 0,
		Action:     types.ActionAllow,
	}, nil
}

func (p *DetectionPipeline) ExecuteStreamWithBuffer(ctx context.Context, accumulatedText string, request *types.RequestContext) (*types.DetectionResult, error) {
	p.mu.RLock()
	detectors := make([]types.Detector, len(p.detectors))
	copy(detectors, p.detectors)
	p.mu.RUnlock()

	for _, detector := range detectors {
		if streamDetector, ok := detector.(types.StreamDetector); ok {
			state := streamDetector.NewStreamState()
			result, err := streamDetector.DetectWithState(ctx, accumulatedText, state)
			if err != nil {
				logrus.Warn("Stream detector error:", detector.Name(), err)
				continue
			}

			if result != nil && result.Matched {
				return result, nil
			}
		} else {
			result, err := detector.StreamDetect(ctx, accumulatedText, request)
			if err != nil {
				logrus.Warn("Stream detector error:", detector.Name(), err)
				continue
			}

			if result != nil && result.Matched {
				return result, nil
			}
		}
	}

	return &types.DetectionResult{
		Tier:       types.Tier1Regex,
		Detector:   "pipeline",
		Category:   types.CategoryOther,
		Severity:   types.SeverityLow,
		Matched:    false,
		Confidence: 0,
		Action:     types.ActionAllow,
	}, nil
}
