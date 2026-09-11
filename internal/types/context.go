package types

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	activePolicy string
	policyMu     sync.RWMutex
)

func SetActivePolicy(policy string) {
	policyMu.Lock()
	defer policyMu.Unlock()
	activePolicy = policy
}

func GetActivePolicy() string {
	policyMu.RLock()
	defer policyMu.RUnlock()
	if activePolicy == "" {
		return "default"
	}
	return activePolicy
}

type RequestContext struct {
	ID                      string              `json:"id"`
	TraceID                 string              `json:"trace_id"`
	StartTime               time.Time           `json:"start_time"`
	ClientIP                string              `json:"client_ip"`
	UserAgent               string              `json:"user_agent"`
	Method                  string              `json:"method"`
	Path                    string              `json:"path"`
	UpstreamURL             string              `json:"upstream_url"`
	RequestHeaders          map[string][]string `json:"request_headers"`
	RequestBody             string              `json:"request_body"`
	RequestBodyHash         string              `json:"request_body_hash,omitempty"`
	ResponseHeaders         map[string][]string `json:"response_headers"`
	ResponseBody            string              `json:"response_body"`
	StatusCode              int                 `json:"status_code"`
	DetectionResults        []DetectionResult   `json:"detection_results"`
	Action                  Action              `json:"action"`
	Error                   string              `json:"error,omitempty"`
	EndTime                 time.Time           `json:"end_time"`
	IsStream                bool                `json:"is_stream"`
	StreamChunks            []string            `json:"stream_chunks,omitempty"`
	ModelName               string              `json:"model_name,omitempty"`
	RequestPurpose          string              `json:"request_purpose,omitempty"`
	ExecutionPolicy         string              `json:"execution_policy,omitempty"`
	ResponseScanningEnabled bool                `json:"response_scanning_enabled,omitempty"`
}

func NewRequestContext() *RequestContext {
	return &RequestContext{
		ID:               uuid.New().String(),
		TraceID:          uuid.New().String(),
		StartTime:        time.Now(),
		RequestHeaders:   make(map[string][]string),
		ResponseHeaders:  make(map[string][]string),
		DetectionResults: make([]DetectionResult, 0),
		StreamChunks:     make([]string, 0),
	}
}

func (rc *RequestContext) Context() context.Context {
	return context.WithValue(context.Background(), "request_id", rc.ID)
}

func (rc *RequestContext) AddDetectionResult(result DetectionResult) {
	rc.DetectionResults = append(rc.DetectionResults, result)
}

func (rc *RequestContext) SetAction(action Action) {
	rc.Action = action
}

func (rc *RequestContext) Complete() {
	rc.EndTime = time.Now()
}

func (rc *RequestContext) Duration() time.Duration {
	return rc.EndTime.Sub(rc.StartTime)
}
