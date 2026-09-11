package types

import "context"

type Detector interface {
	Name() string
	Tier() DetectionTier
	Detect(ctx context.Context, request *RequestContext) (*DetectionResult, error)
	StreamDetect(ctx context.Context, chunk string, request *RequestContext) (*DetectionResult, error)
}

type StreamDetector interface {
	Detector
	NewStreamState() StreamState
	DetectWithState(ctx context.Context, accumulatedText string, state StreamState) (*DetectionResult, error)
}

type StreamState interface {
	Reset()
}

type AuditLogger interface {
	Log(ctx context.Context, request *RequestContext) error
	LogStreamChunk(ctx context.Context, request *RequestContext, chunk string) error
}

type ProxyHandler interface {
	Handle(ctx context.Context, request *RequestContext) error
	HandleStream(ctx context.Context, request *RequestContext) error
}

type Pipeline interface {
	AddDetector(detector Detector)
	Execute(ctx context.Context, request *RequestContext) (*DetectionResult, error)
	ExecuteStream(ctx context.Context, chunk string, request *RequestContext) (*DetectionResult, error)
}

type ConfigWatcher interface {
	Watch(callback func()) error
	Close() error
}
