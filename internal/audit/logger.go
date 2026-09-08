package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"llm-audit-gateway/internal/config"
	"llm-audit-gateway/internal/types"
)

type AuditLogger struct {
	config            *config.Config
	logDir            string
	buffer            chan *types.RequestContext
	wg                sync.WaitGroup
	stopChan          chan bool
	mu                sync.RWMutex
	closing           bool
	stateMu           sync.Mutex
	pending           sync.WaitGroup
	previousHash      string
	hashMu            sync.RWMutex
	diskUsageExceeded bool
	diskMu            sync.RWMutex
	sessionAggregator *sessionAggregator
}

type sessionAggregator struct {
	mu            sync.RWMutex
	sessions      map[string]*sessionState
	timeout       time.Duration
	cleanupTicker *time.Ticker
}

type sessionState struct {
	TraceID          string
	RequestID        string
	StartTime        time.Time
	LastActivityTime time.Time
	ClientIP         string
	RequestBody      string
	ResponseBody     string
	DetectionResults []types.DetectionResult
	StreamChunks     []string
	Action           types.Action
	StatusCode       int
}

func newSessionAggregator(timeout time.Duration) *sessionAggregator {
	sa := &sessionAggregator{
		sessions: make(map[string]*sessionState),
		timeout:  timeout,
	}

	sa.cleanupTicker = time.NewTicker(timeout / 2)
	go sa.startCleanup()

	return sa
}

func (sa *sessionAggregator) startCleanup() {
	for range sa.cleanupTicker.C {
		sa.cleanupExpired()
	}
}

func (sa *sessionAggregator) cleanupExpired() {
	sa.mu.Lock()
	defer sa.mu.Unlock()

	now := time.Now()
	for traceID, session := range sa.sessions {
		if now.Sub(session.LastActivityTime) > sa.timeout {
			delete(sa.sessions, traceID)
		}
	}
}

func (sa *sessionAggregator) UpdateSession(ctx *types.RequestContext, chunk string) {
	sa.mu.Lock()
	defer sa.mu.Unlock()

	state, ok := sa.sessions[ctx.TraceID]
	if !ok {
		state = &sessionState{
			TraceID:          ctx.TraceID,
			RequestID:        ctx.ID,
			StartTime:        ctx.StartTime,
			DetectionResults: make([]types.DetectionResult, 0),
			StreamChunks:     make([]string, 0),
		}
		sa.sessions[ctx.TraceID] = state
	}

	state.LastActivityTime = time.Now()
	state.ClientIP = ctx.ClientIP

	if ctx.RequestBody != "" {
		state.RequestBody = ctx.RequestBody
	}

	if ctx.ResponseBody != "" {
		state.ResponseBody = ctx.ResponseBody
	}

	state.StatusCode = ctx.StatusCode
	state.Action = ctx.Action

	if len(ctx.DetectionResults) > 0 {
		state.DetectionResults = append(state.DetectionResults, ctx.DetectionResults...)
	}

	if chunk != "" {
		state.StreamChunks = append(state.StreamChunks, chunk)
	}
}

func (sa *sessionAggregator) Aggregate(ctx *types.RequestContext) *sessionState {
	sa.mu.Lock()
	defer sa.mu.Unlock()

	state, ok := sa.sessions[ctx.TraceID]
	if !ok {
		state = &sessionState{
			TraceID:          ctx.TraceID,
			RequestID:        ctx.ID,
			StartTime:        ctx.StartTime,
			DetectionResults: make([]types.DetectionResult, 0),
			StreamChunks:     make([]string, 0),
		}
	}

	state.LastActivityTime = time.Now()
	state.ClientIP = ctx.ClientIP

	if ctx.RequestBody != "" {
		state.RequestBody = ctx.RequestBody
	}

	if ctx.ResponseBody != "" {
		state.ResponseBody = ctx.ResponseBody
	}

	state.StatusCode = ctx.StatusCode
	state.Action = ctx.Action

	if len(ctx.DetectionResults) > 0 {
		state.DetectionResults = append(state.DetectionResults, ctx.DetectionResults...)
	}

	if len(ctx.StreamChunks) > 0 {
		state.StreamChunks = append(state.StreamChunks, ctx.StreamChunks...)
	}

	if ctx.EndTime.After(state.StartTime) {
		delete(sa.sessions, ctx.TraceID)
		return state
	}

	return nil
}

func (sa *sessionAggregator) Close() {
	sa.cleanupTicker.Stop()
}

// FlushAll returns and clears every in-flight session so a graceful shutdown
// does not drop stream records that never reached their final Log() call.
func (sa *sessionAggregator) FlushAll() []*sessionState {
	sa.mu.Lock()
	defer sa.mu.Unlock()

	states := make([]*sessionState, 0, len(sa.sessions))
	for _, state := range sa.sessions {
		states = append(states, state)
	}
	sa.sessions = make(map[string]*sessionState)
	return states
}

func NewAuditLogger(cfg *config.Config) (*AuditLogger, error) {
	logger := &AuditLogger{
		config:            cfg,
		logDir:            "logs/audit",
		buffer:            make(chan *types.RequestContext, 1000),
		stopChan:          make(chan bool),
		sessionAggregator: newSessionAggregator(5 * time.Minute),
	}

	if err := os.MkdirAll(logger.logDir, 0755); err != nil {
		return nil, err
	}

	logger.startWorker()
	logger.startDiskMonitor()

	return logger, nil
}

// SetLogDir points the logger at an explicit directory (used by tests so they
// do not pollute the repository with logs/audit output).
func (al *AuditLogger) SetLogDir(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	al.mu.Lock()
	defer al.mu.Unlock()
	al.logDir = dir
	return nil
}

func (al *AuditLogger) startWorker() {
	al.wg.Add(1)
	go func() {
		defer al.wg.Done()
		for {
			select {
			case reqCtx := <-al.buffer:
				al.writeLog(reqCtx)
			case <-al.stopChan:
				// Drain everything already queued before exiting. Logs arriving
				// after Close began bypass the channel and write synchronously.
				for {
					select {
					case reqCtx := <-al.buffer:
						al.writeLog(reqCtx)
					default:
						return
					}
				}
			}
		}
	}()
}

func (al *AuditLogger) configEnabled() bool {
	al.mu.RLock()
	defer al.mu.RUnlock()
	if al.config == nil {
		return false
	}
	return al.config.Audit.Enabled
}

func (al *AuditLogger) configStorageType() string {
	al.mu.RLock()
	defer al.mu.RUnlock()
	if al.config == nil {
		return "file"
	}
	return al.config.Audit.StorageType
}

func (al *AuditLogger) auditConfig() config.AuditConfig {
	al.mu.RLock()
	defer al.mu.RUnlock()
	if al.config == nil {
		return config.AuditConfig{}
	}
	return al.config.Audit
}

func (al *AuditLogger) startDiskMonitor() {
	al.wg.Add(1)
	go func() {
		defer al.wg.Done()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				al.checkDiskUsage()
				al.cleanupOldLogs()
			case <-al.stopChan:
				return
			}
		}
	}()
}

func (al *AuditLogger) checkDiskUsage() {
	maxUsage := al.auditConfig().MaxDiskUsagePercent
	if maxUsage == 0 {
		maxUsage = 85
	}

	usedPercent, err := diskUsagePercent(al.logDir)
	if err != nil {
		logrus.Warn("Failed to check disk usage:", err)
		return
	}

	al.diskMu.Lock()
	if usedPercent > int64(maxUsage) {
		if !al.diskUsageExceeded {
			logrus.Warnf("Disk usage exceeded %d%% threshold, audit logging may be disabled", maxUsage)
			al.diskUsageExceeded = true
		}
	} else {
		if al.diskUsageExceeded {
			logrus.Info("Disk usage back to normal, audit logging resumed")
			al.diskUsageExceeded = false
		}
	}
	al.diskMu.Unlock()
}

func (al *AuditLogger) cleanupOldLogs() {
	retentionDays := al.auditConfig().LogRetentionDays
	if retentionDays == 0 {
		retentionDays = 90
	}

	cutoffTime := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)

	err := filepath.Walk(al.logDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasPrefix(info.Name(), "audit-") && info.ModTime().Before(cutoffTime) {
			if err := os.Remove(path); err != nil {
				logrus.Error("Failed to remove old log file:", path, err)
			} else {
				logrus.Info("Cleaned up old log file:", path)
			}
		}

		return nil
	})

	if err != nil {
		logrus.Error("Failed to cleanup old logs:", err)
	}
}

func (al *AuditLogger) isDiskExceeded() bool {
	al.diskMu.RLock()
	defer al.diskMu.RUnlock()
	return al.diskUsageExceeded
}

func (al *AuditLogger) Log(ctx context.Context, request *types.RequestContext) error {
	if !al.configEnabled() || al.isDiskExceeded() {
		return nil
	}

	al.stateMu.Lock()
	if al.closing {
		// Close() has started; the worker may no longer read the channel, so
		// fall through to a synchronous write to avoid dropping the record.
		al.stateMu.Unlock()
		al.writeLog(request)
		return nil
	}
	al.pending.Add(1)
	al.stateMu.Unlock()
	defer al.pending.Done()

	select {
	case al.buffer <- request:
		return nil
	default:
		// Never drop audit records because of a full buffer: degrade to a
		// synchronous write so the log still lands on disk.
		logrus.Warn("Audit log buffer is full; writing synchronously")
	}

	al.writeLog(request)
	return nil
}

func (al *AuditLogger) LogStreamChunk(ctx context.Context, request *types.RequestContext, chunk string) error {
	if !al.configEnabled() || al.isDiskExceeded() {
		return nil
	}

	al.sessionAggregator.UpdateSession(request, chunk)

	return nil
}

func (al *AuditLogger) writeLog(request *types.RequestContext) {
	if request.IsStream {
		session := al.sessionAggregator.Aggregate(request)
		if session == nil {
			return
		}
		if !al.shouldWriteLog(session.Action, session.DetectionResults) {
			return
		}
		al.writeSessionLog(session)
		return
	}

	if !al.shouldWriteLog(request.Action, request.DetectionResults) {
		return
	}

	switch al.configStorageType() {
	case "kafka":
		al.writeToKafka(request)
	default:
		al.writeToFile(request)
	}
}

func (al *AuditLogger) writeSessionLog(session *sessionState) {
	al.mu.Lock()
	defer al.mu.Unlock()

	dateStr := time.Now().Format("2006-01-02")
	fileName := filepath.Join(al.logDir, "audit-"+dateStr+".log")

	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		logrus.Error("Failed to open audit log file:", err)
		return
	}
	defer file.Close()

	logEntry := FormatSessionLogEntry(session)

	al.hashMu.RLock()
	logEntry.PreviousHash = al.previousHash
	al.hashMu.RUnlock()

	logEntry.AuditHash = logEntry.ComputeHash()

	al.hashMu.Lock()
	al.previousHash = logEntry.AuditHash
	al.hashMu.Unlock()

	data, err := logEntry.ToJSON()
	if err != nil {
		logrus.Error("Failed to marshal audit log:", err)
		return
	}

	if _, err := file.WriteString(string(data) + "\n"); err != nil {
		logrus.Error("Failed to write audit log:", err)
	}
}

func (al *AuditLogger) writeToFile(request *types.RequestContext) {
	al.mu.Lock()
	defer al.mu.Unlock()

	dateStr := time.Now().Format("2006-01-02")
	fileName := filepath.Join(al.logDir, "audit-"+dateStr+".log")

	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		logrus.Error("Failed to open audit log file:", err)
		return
	}
	defer file.Close()

	logEntry := FormatLogEntry(request)

	al.hashMu.RLock()
	logEntry.PreviousHash = al.previousHash
	al.hashMu.RUnlock()

	logEntry.AuditHash = logEntry.ComputeHash()

	al.hashMu.Lock()
	al.previousHash = logEntry.AuditHash
	al.hashMu.Unlock()

	data, err := logEntry.ToJSON()
	if err != nil {
		logrus.Error("Failed to marshal audit log:", err)
		return
	}

	if _, err := file.WriteString(string(data) + "\n"); err != nil {
		logrus.Error("Failed to write audit log:", err)
	}
}

func (al *AuditLogger) writeToKafka(request *types.RequestContext) {
	logrus.Info("Kafka audit logging not implemented yet")
}

func (al *AuditLogger) Close() {
	al.stateMu.Lock()
	if al.closing {
		al.stateMu.Unlock()
		return
	}
	al.closing = true
	al.stateMu.Unlock()

	// Persist stream sessions that never reached their final Log() call.
	for _, state := range al.sessionAggregator.FlushAll() {
		if al.shouldWriteLog(state.Action, state.DetectionResults) {
			al.writeSessionLog(state)
		}
	}

	close(al.stopChan)
	al.sessionAggregator.Close()
	al.wg.Wait()

	// Wait for producers that passed the closing check just before Close and
	// then drain whatever they queued after the worker exited.
	al.pending.Wait()
	for {
		select {
		case reqCtx := <-al.buffer:
			al.writeLog(reqCtx)
		default:
			return
		}
	}
}

func (al *AuditLogger) QueryByTraceID(traceID string) (*SessionLogEntry, error) {
	files, err := filepath.Glob(filepath.Join(al.logDir, "audit-*.log"))
	if err != nil {
		return nil, err
	}

	for i := len(files) - 1; i >= 0; i-- {
		data, err := os.ReadFile(files[i])
		if err != nil {
			continue
		}

		// Log entries are written as (possibly indented) JSON objects. Use a
		// streaming decoder so each object is parsed correctly regardless of
		// formatting/newlines, rather than splitting by line.
		dec := json.NewDecoder(bytes.NewReader(data))
		for dec.More() {
			var entry SessionLogEntry
			if err := dec.Decode(&entry); err != nil {
				break
			}

			if entry.SessionID == traceID || entry.RequestID == traceID {
				return &entry, nil
			}
		}
	}

	return nil, nil
}

func (al *AuditLogger) UpdateConfig(cfg *config.Config) {
	al.mu.Lock()
	defer al.mu.Unlock()
	al.config = cfg
}

func computeSHA256(content string) string {
	h := sha256.New()
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}

func (al *AuditLogger) shouldWriteLog(action types.Action, results []types.DetectionResult) bool {
	if action == types.ActionBlock {
		return true
	}

	isHighRisk := false
	for _, result := range results {
		if result.Matched && (result.Severity == types.SeverityCritical || result.Severity == types.SeverityHigh) {
			isHighRisk = true
			break
		}
	}

	if isHighRisk {
		return true
	}

	al.mu.RLock()
	samplingRate := al.config.Audit.AuditSamplingRate
	al.mu.RUnlock()

	if samplingRate <= 0 || samplingRate >= 1 {
		return true
	}

	return rand.Float64() <= samplingRate
}
