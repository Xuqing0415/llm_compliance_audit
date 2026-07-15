package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"llm-audit-gateway/internal/types"
)

type LogEntry struct {
	Timestamp        time.Time              `json:"timestamp"`
	RequestID        string                 `json:"request_id"`
	TraceID          string                 `json:"trace_id"`
	ClientIP         string                 `json:"client_ip"`
	UserAgent        string                 `json:"user_agent"`
	Method           string                 `json:"method"`
	Path             string                 `json:"path"`
	UpstreamURL      string                 `json:"upstream_url"`
	RequestBody      string                 `json:"request_body"`
	ResponseBody     string                 `json:"response_body"`
	StatusCode       int                    `json:"status_code"`
	DetectionResults []types.DetectionResult `json:"detection_results"`
	Action           types.Action           `json:"action"`
	Error            string                 `json:"error,omitempty"`
	Duration         float64                `json:"duration_ms"`
	IsStream         bool                   `json:"is_stream"`
	ModelName        string                 `json:"model_name,omitempty"`
	StreamChunks     []string               `json:"stream_chunks,omitempty"`
	Sensitivity      string                 `json:"sensitivity,omitempty"`
	AuditHash        string                 `json:"audit_hash"`
	PreviousHash     string                 `json:"previous_hash"`
}

func FormatLogEntry(request *types.RequestContext) *LogEntry {
	sensitivity := computeSensitivity(request)

	return &LogEntry{
		Timestamp:        time.Now(),
		RequestID:        request.ID,
		TraceID:          request.TraceID,
		ClientIP:         request.ClientIP,
		UserAgent:        request.UserAgent,
		Method:           request.Method,
		Path:             request.Path,
		UpstreamURL:      request.UpstreamURL,
		RequestBody:      request.RequestBody,
		ResponseBody:     request.ResponseBody,
		StatusCode:       request.StatusCode,
		DetectionResults: request.DetectionResults,
		Action:           request.Action,
		Error:            request.Error,
		Duration:         float64(request.Duration().Milliseconds()),
		IsStream:         request.IsStream,
		ModelName:        request.ModelName,
		StreamChunks:     request.StreamChunks,
		Sensitivity:      sensitivity,
	}
}

func (entry *LogEntry) ComputeHash() string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%d|%s|%f",
		entry.Timestamp.Format(time.RFC3339),
		entry.RequestID,
		entry.Method,
		entry.Path,
		entry.ClientIP,
		entry.StatusCode,
		entry.Action,
		entry.Duration,
	)

	if entry.PreviousHash != "" {
		data = entry.PreviousHash + "|" + data
	}

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (entry *LogEntry) ToJSON() ([]byte, error) {
	return json.MarshalIndent(entry, "", "  ")
}

func (entry *LogEntry) ToCSV() string {
	return fmt.Sprintf("%s,%s,%s,%s,%s,%s,%d,%s,%f",
		entry.Timestamp.Format(time.RFC3339),
		entry.RequestID,
		entry.ClientIP,
		entry.Method,
		entry.Path,
		entry.Action,
		entry.StatusCode,
		entry.ModelName,
		entry.Duration,
	)
}

type SessionLogEntry struct {
	Timestamp        time.Time              `json:"timestamp"`
	SessionID        string                 `json:"session_id"`
	RequestID        string                 `json:"request_id"`
	ClientIP         string                 `json:"client_ip"`
	RequestBody      string                 `json:"request_body"`
	ResponseBody     string                 `json:"response_body"`
	ResponseBodyHash string                 `json:"response_body_hash"`
	StatusCode       int                    `json:"status_code"`
	Action           types.Action           `json:"action"`
	Duration         float64                `json:"duration_ms"`
	IsStream         bool                   `json:"is_stream"`
	TriggeredRules   []string               `json:"triggered_rules"`
	FinalSeverity    types.DetectionSeverity `json:"final_severity"`
	DetectionResults []types.DetectionResult `json:"detection_results"`
	Sensitivity      string                 `json:"sensitivity,omitempty"`
	AuditHash        string                 `json:"audit_hash"`
	PreviousHash     string                 `json:"previous_hash"`
}

func FormatSessionLogEntry(session *sessionState) *SessionLogEntry {
	triggeredRules := make([]string, 0)
	finalSeverity := types.SeverityLow

	for _, result := range session.DetectionResults {
		if result.Matched && result.HitRuleID != "" {
			triggeredRules = append(triggeredRules, result.HitRuleID)
		}
		if result.Severity > finalSeverity {
			finalSeverity = result.Severity
		}
	}

	sensitivity := computeSessionSensitivity(session.Action, session.DetectionResults)

	fullResponseBody := ""
	for _, chunk := range session.StreamChunks {
		fullResponseBody += chunk
	}
	if fullResponseBody == "" {
		fullResponseBody = session.ResponseBody
	}

	responseBodyHash := ""
	if fullResponseBody != "" {
		hash := sha256.Sum256([]byte(fullResponseBody))
		responseBodyHash = hex.EncodeToString(hash[:])
	}

	truncatedBody := fullResponseBody
	if len(truncatedBody) > 100 {
		truncatedBody = truncatedBody[:100] + "..."
	}

	return &SessionLogEntry{
		Timestamp:        time.Now(),
		SessionID:        session.TraceID,
		RequestID:        session.RequestID,
		ClientIP:         session.ClientIP,
		RequestBody:      session.RequestBody,
		ResponseBody:     truncatedBody,
		ResponseBodyHash: responseBodyHash,
		StatusCode:       session.StatusCode,
		Action:           session.Action,
		Duration:         float64(time.Since(session.StartTime).Milliseconds()),
		IsStream:         true,
		TriggeredRules:   triggeredRules,
		FinalSeverity:    finalSeverity,
		DetectionResults: session.DetectionResults,
		Sensitivity:      sensitivity,
	}
}

func computeSensitivity(request *types.RequestContext) string {
	if request.Action == types.ActionBlock {
		return "Critical"
	}

	for _, result := range request.DetectionResults {
		if result.Matched {
			switch result.Severity {
			case types.SeverityCritical, types.SeverityHigh:
				return "Critical"
			case types.SeverityMedium:
				return "Medium"
			default:
				return "Low"
			}
		}
	}

	if request.Action == types.ActionAlert || request.Action == types.ActionPassThroughWithWarning {
		return "Medium"
	}

	return "Low"
}

func computeSessionSensitivity(action types.Action, results []types.DetectionResult) string {
	if action == types.ActionBlock {
		return "Critical"
	}

	for _, result := range results {
		if result.Matched {
			switch result.Severity {
			case types.SeverityCritical, types.SeverityHigh:
				return "Critical"
			case types.SeverityMedium:
				return "Medium"
			default:
				return "Low"
			}
		}
	}

	if action == types.ActionAlert || action == types.ActionPassThroughWithWarning {
		return "Medium"
	}

	return "Low"
}

func (entry *SessionLogEntry) ComputeHash() string {
	data := fmt.Sprintf("%s|%s|%s|%d|%s|%f",
		entry.Timestamp.Format(time.RFC3339),
		entry.SessionID,
		entry.ClientIP,
		entry.StatusCode,
		entry.Action,
		entry.Duration,
	)

	if entry.PreviousHash != "" {
		data = entry.PreviousHash + "|" + data
	}

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (entry *SessionLogEntry) ToJSON() ([]byte, error) {
	return json.MarshalIndent(entry, "", "  ")
}