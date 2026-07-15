package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"llm-audit-gateway/internal/config"
	"llm-audit-gateway/internal/stream"
	"llm-audit-gateway/internal/types"
)

type peekReader struct {
	io.ReadCloser
	buf []byte
}

func (pr *peekReader) Read(p []byte) (int, error) {
	if len(pr.buf) > 0 {
		n := copy(p, pr.buf)
		pr.buf = pr.buf[n:]
		return n, nil
	}
	return pr.ReadCloser.Read(p)
}

type ProxyHandler struct {
	proxy         *httputil.ReverseProxy
	upstreamURL   *url.URL
	config        *config.Config
	mu            sync.RWMutex
	detectionFunc func(ctx context.Context, request *types.RequestContext) (*types.DetectionResult, error)
	streamDetectFunc func(ctx context.Context, accumulatedText string, request *types.RequestContext) (*types.DetectionResult, error)
	auditFunc     func(ctx context.Context, request *types.RequestContext) error
	bypassMode    bool
	bypassMu      sync.RWMutex
}

func NewProxyHandler(cfg *config.Config) (*ProxyHandler, error) {
	upstreamURL, err := url.Parse(cfg.Upstream.URL)
	if err != nil {
		return nil, err
	}

	ph := &ProxyHandler{
		upstreamURL: upstreamURL,
		config:      cfg,
	}

	ph.proxy = &httputil.ReverseProxy{
		Director: ph.director,
		Transport: &http.Transport{
			MaxIdleConns:        cfg.Upstream.MaxConnections,
			MaxIdleConnsPerHost: cfg.Upstream.MaxConnections,
			IdleConnTimeout:     30 * time.Second,
		},
		ModifyResponse: ph.modifyResponse,
		ErrorHandler:   ph.errorHandler,
	}

	return ph, nil
}

func (ph *ProxyHandler) SetDetectionFunc(fn func(ctx context.Context, request *types.RequestContext) (*types.DetectionResult, error)) {
	ph.detectionFunc = fn
}

func (ph *ProxyHandler) SetStreamDetectFunc(fn func(ctx context.Context, accumulatedText string, request *types.RequestContext) (*types.DetectionResult, error)) {
	ph.streamDetectFunc = fn
}

func (ph *ProxyHandler) SetAuditFunc(fn func(ctx context.Context, request *types.RequestContext) error) {
	ph.auditFunc = fn
}

func (ph *ProxyHandler) UpdateConfig(cfg *config.Config) error {
	ph.mu.Lock()
	defer ph.mu.Unlock()

	upstreamURL, err := url.Parse(cfg.Upstream.URL)
	if err != nil {
		return err
	}

	ph.upstreamURL = upstreamURL
	ph.config = cfg

	ph.proxy.Transport = &http.Transport{
		MaxIdleConns:        cfg.Upstream.MaxConnections,
		MaxIdleConnsPerHost: cfg.Upstream.MaxConnections,
		IdleConnTimeout:     30 * time.Second,
	}

	return nil
}

func (ph *ProxyHandler) SetBypassMode(bypass bool) {
	ph.bypassMu.Lock()
	defer ph.bypassMu.Unlock()
	ph.bypassMode = bypass
	if bypass {
		logrus.Warn("Bypass mode enabled: all detection skipped, gateway acts as pure proxy")
	} else {
		logrus.Info("Bypass mode disabled: detection pipeline resumed")
	}
}

func (ph *ProxyHandler) IsBypassMode() bool {
	ph.bypassMu.RLock()
	defer ph.bypassMu.RUnlock()
	return ph.bypassMode
}

func (ph *ProxyHandler) extractRequestPurpose(c *gin.Context) string {
	if purpose := c.GetHeader("X-Request-Purpose"); purpose != "" {
		return purpose
	}

	if purpose := c.GetHeader("X-Flow-Type"); purpose != "" {
		return purpose
	}

	ph.mu.RLock()
	mappings := ph.config.Detection.PathPurposeMappings
	ph.mu.RUnlock()

	for _, mapping := range mappings {
		if strings.Contains(c.Request.URL.Path, mapping.Pattern) {
			return mapping.Purpose
		}
	}

	if strings.Contains(c.Request.URL.Path, "/export") {
		return "export"
	}

	if strings.Contains(c.Request.URL.Path, "/codegen") ||
		strings.Contains(c.Request.URL.Path, "/code") {
		return "codegen"
	}

	if strings.Contains(c.Request.URL.Path, "/api/chat/completions") {
		return "chat"
	}

	return ""
}

func (ph *ProxyHandler) shouldUseStreaming(c *gin.Context, purpose string) bool {
	if purpose == "export-batch" ||
		strings.Contains(c.Request.URL.Path, "/batch") ||
		strings.Contains(c.Request.URL.Path, "/download") {
		return false
	}

	if purpose == "export" {
		if strings.Contains(c.GetHeader("Accept"), "text/event-stream") {
			return true
		}
		return false
	}

	return strings.Contains(c.GetHeader("Accept"), "text/event-stream") ||
		strings.Contains(c.GetHeader("Content-Type"), "text/event-stream") ||
		strings.Contains(c.Request.URL.Path, "/stream")
}

func (ph *ProxyHandler) extractExecutionPolicy(c *gin.Context) string {
	globalPolicy := types.GetActivePolicy()
	if globalPolicy != "default" {
		switch globalPolicy {
		case "fallback-audit":
			return "force_audit"
		case "force-block":
			return "force_block"
		}
	}

	ph.mu.RLock()
	policies := ph.config.Detection.ExecutionPolicies
	ph.mu.RUnlock()

	if len(policies) == 0 {
		return ""
	}

	for _, policy := range policies {
		headerValue := c.GetHeader(policy.HeaderKey)
		if headerValue == "" {
			continue
		}

		for _, allowedValue := range policy.HeaderValues {
			if strings.EqualFold(headerValue, allowedValue) {
				return policy.Mode
			}
		}
	}

	return ""
}

func (ph *ProxyHandler) director(req *http.Request) {
	req.URL.Scheme = ph.upstreamURL.Scheme
	req.URL.Host = ph.upstreamURL.Host
	req.URL.Path = ph.upstreamURL.Path + req.URL.Path
	req.URL.RawQuery = req.URL.RawQuery

	req.Header.Set("Host", ph.upstreamURL.Host)

	for k, v := range ph.config.Upstream.RequestHeaders {
		req.Header.Set(k, v)
	}
}

func (ph *ProxyHandler) modifyResponse(resp *http.Response) error {
	return nil
}

func (ph *ProxyHandler) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	logrus.Error("Proxy error:", err)
	http.Error(w, "Gateway error", http.StatusBadGateway)
}

func (ph *ProxyHandler) ServeHTTP(c *gin.Context) {
	reqCtx := types.NewRequestContext()
	reqCtx.ClientIP = c.ClientIP()
	reqCtx.UserAgent = c.Request.UserAgent()
	reqCtx.Method = c.Request.Method
	reqCtx.Path = c.Request.URL.Path
	reqCtx.RequestHeaders = make(map[string][]string)

	for k, v := range c.Request.Header {
		reqCtx.RequestHeaders[k] = v
	}

	reqCtx.RequestPurpose = ph.extractRequestPurpose(c)
	reqCtx.ExecutionPolicy = ph.extractExecutionPolicy(c)
	reqCtx.ResponseScanningEnabled = reqCtx.RequestPurpose != "export" && reqCtx.RequestPurpose != "export-batch"

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logrus.Error("Failed to read request body:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
		return
	}

	fullBody := string(body)
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	h := sha256.New()
	h.Write(body)
	reqCtx.RequestBodyHash = hex.EncodeToString(h.Sum(nil))

	maxLen := ph.config.Detection.MaxDetectionLength
	if maxLen <= 0 {
		maxLen = 2000
	}

	if len(fullBody) > maxLen {
		logrus.Debugf("Request body truncated from %d to %d chars for detection", len(fullBody), maxLen)
		reqCtx.RequestBody = fullBody[:maxLen]
	} else {
		reqCtx.RequestBody = fullBody
	}

	reqCtx.IsStream = ph.shouldUseStreaming(c, reqCtx.RequestPurpose)

	if !ph.IsBypassMode() && ph.detectionFunc != nil {
		result, err := ph.detectionFunc(reqCtx.Context(), reqCtx)
		if err != nil {
			logrus.Error("Detection error:", err)
			if !ph.config.Detection.FailOpen {
				c.JSON(http.StatusForbidden, gin.H{"error": "Detection failed", "action": "BLOCK"})
				return
			}
		}

		if result != nil && result.Matched {
			shouldBlock := false

			switch reqCtx.ExecutionPolicy {
			case "force_block":
				shouldBlock = result.Action == types.ActionBlock
			case "force_audit":
				shouldBlock = false
			default:
				shouldBlock = result.Action == types.ActionBlock && !ph.config.Detection.AuditOnlyMode
			}

			if shouldBlock {
				c.JSON(http.StatusForbidden, gin.H{
					"error":        "Request blocked by audit gateway",
					"reason":       result.Message,
					"category":     result.Category,
					"severity":     result.Severity,
					"detection_id": reqCtx.ID,
					"policy":       reqCtx.ExecutionPolicy,
				})
				if ph.auditFunc != nil {
					go ph.auditFunc(reqCtx.Context(), reqCtx)
				}
				return
			}

			if result.Action == types.ActionPassThroughWithWarning {
				logrus.Warnf("Pass-through with warning: request=%s, rule=%s, severity=%s", reqCtx.ID, result.HitRuleID, result.Severity)
			}

			reqCtx.AddDetectionResult(*result)
			reqCtx.SetAction(result.Action)
		}
	} else if ph.IsBypassMode() {
		reqCtx.SetAction(types.ActionAllow)
	}

	if ph.shouldUseStreaming(c, reqCtx.RequestPurpose) {
		logrus.Debugf("Route decision: handleStream for path=%s, purpose=%s", c.Request.URL.Path, reqCtx.RequestPurpose)
		ph.handleStream(c, reqCtx)
	} else {
		logrus.Debugf("Route decision: handleNormal for path=%s, purpose=%s", c.Request.URL.Path, reqCtx.RequestPurpose)
		ph.handleNormal(c, reqCtx)
	}

	if ph.auditFunc != nil {
		go ph.auditFunc(reqCtx.Context(), reqCtx)
	}
}

func (ph *ProxyHandler) handleNormal(c *gin.Context, reqCtx *types.RequestContext) {
	ph.mu.RLock()
	defer ph.mu.RUnlock()

	bodyBuffer := &bytes.Buffer{}
	writer := &responseWriter{ResponseWriter: c.Writer, body: bodyBuffer}

	ph.proxy.ServeHTTP(writer, c.Request)

	reqCtx.StatusCode = writer.Status()
	reqCtx.ResponseHeaders = make(map[string][]string)
	for k, v := range writer.Header() {
		reqCtx.ResponseHeaders[k] = v
	}

	reqCtx.ResponseBody = bodyBuffer.String()

	if ph.detectionFunc != nil && reqCtx.ResponseBody != "" && reqCtx.ResponseScanningEnabled {
		respCtx := &types.RequestContext{
			RequestBody: reqCtx.ResponseBody,
		}
		result, err := ph.detectionFunc(reqCtx.Context(), respCtx)
		if err != nil {
			logrus.Error("Response detection error:", err)
		}

		if result != nil && result.Matched {
			reqCtx.AddDetectionResult(*result)

			shouldBlock := false
			switch reqCtx.ExecutionPolicy {
			case "force_block":
				shouldBlock = result.Action == types.ActionBlock
			case "force_audit":
				shouldBlock = false
			default:
				shouldBlock = result.Action == types.ActionBlock && !ph.config.Detection.AuditOnlyMode
			}

			if shouldBlock {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":        "Response blocked by audit gateway",
					"reason":       result.Message,
					"category":     result.Category,
					"severity":     result.Severity,
					"detection_id": reqCtx.ID,
					"policy":       reqCtx.ExecutionPolicy,
				})
				return
			}
		}
	}

	reqCtx.Complete()
}

type responseWriter struct {
	http.ResponseWriter
	body *bytes.Buffer
}

func (w *responseWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func (w *responseWriter) Status() int {
	return http.StatusOK
}

func (ph *ProxyHandler) handleStream(c *gin.Context, reqCtx *types.RequestContext) {
	ph.mu.RLock()
	upstreamURL := *ph.upstreamURL
	streamCfg := ph.config.Detection.Stream
	auditOnly := ph.config.Detection.AuditOnlyMode
	policy := reqCtx.ExecutionPolicy
	ph.mu.RUnlock()

	fullURL := upstreamURL.String() + reqCtx.Path

	upstreamReq, err := http.NewRequest(reqCtx.Method, fullURL, bytes.NewBufferString(reqCtx.RequestBody))
	if err != nil {
		logrus.Error("Failed to create upstream request:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create upstream request"})
		return
	}

	for k, v := range reqCtx.RequestHeaders {
		upstreamReq.Header[k] = v
	}

	for k, v := range ph.config.Upstream.RequestHeaders {
		upstreamReq.Header.Set(k, v)
	}

	client := &http.Client{
		Timeout: time.Duration(ph.config.Upstream.Timeout) * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        ph.config.Upstream.MaxConnections,
			MaxIdleConnsPerHost: ph.config.Upstream.MaxConnections,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	resp, err := client.Do(upstreamReq)
	if err != nil {
		logrus.Error("Failed to connect to upstream:", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to connect to upstream"})
		return
	}
	defer resp.Body.Close()

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Flush()

	if ph.IsBypassMode() || !reqCtx.ResponseScanningEnabled {
		io.Copy(c.Writer, resp.Body)
		c.Writer.Flush()
		reqCtx.StatusCode = resp.StatusCode
		reqCtx.Complete()
		return
	}

	peekBuffer := make([]byte, 1024)
	peekN, err := resp.Body.Read(peekBuffer)
	if err != nil && err != io.EOF {
		logrus.Error("Failed to peek response body:", err)
		io.Copy(c.Writer, resp.Body)
		c.Writer.Flush()
		reqCtx.StatusCode = resp.StatusCode
		reqCtx.Complete()
		return
	}

	isSSEFormat := strings.HasPrefix(strings.TrimSpace(string(peekBuffer[:peekN])), "data:")

	if !isSSEFormat {
		logrus.Warnf("Response is not SSE format (path=%s), falling back to direct passthrough", c.Request.URL.Path)
		c.Writer.Header().Del("Content-Type")
		c.Writer.Header().Del("Transfer-Encoding")
		c.Writer.Header().Del("Cache-Control")
		c.Writer.Header().Del("Connection")

		c.Writer.Write(peekBuffer[:peekN])
		io.Copy(c.Writer, resp.Body)
		c.Writer.Flush()
		reqCtx.StatusCode = resp.StatusCode
		reqCtx.Complete()
		return
	}

	resp.Body = &peekReader{ReadCloser: resp.Body, buf: peekBuffer[:peekN]}

	parser := stream.NewSSEParser(resp.Body)
	window := stream.NewSlidingWindow(streamCfg.WindowMaxSize, streamCfg.WindowFlushThreshold)

	lastFlushTime := time.Now()
	blocked := false
	var blockResult *types.DetectionResult

	for {
		event, err := parser.ReadEvent()
		if err != nil {
			if err != io.EOF {
				logrus.Error("Stream read error:", err)
			}
			break
		}

		if event.Data == "" {
			continue
		}

		content, isDone := stream.ExtractContentFromSSEData(event.Data)

		if content != "" {
			window.Append(content)
			reqCtx.StreamChunks = append(reqCtx.StreamChunks, content)
		}

		now := time.Now()
		shouldFlush := window.UnflushedSize() >= streamCfg.WindowFlushThreshold ||
			now.Sub(lastFlushTime).Milliseconds() >= int64(streamCfg.MaxDelayMs)

		if shouldFlush && !blocked {
			toFlush, flushed := window.Flush()
			if flushed {
				c.Writer.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"" + escapeJSON(toFlush) + "\"}}]}\n\n"))
				c.Writer.Flush()
				lastFlushTime = now
			}
		}

		if ph.streamDetectFunc != nil && !blocked {
			accumulated := window.GetCurrentBuffer()
			if len(accumulated) >= streamCfg.WindowFlushThreshold {
				result, err := ph.streamDetectFunc(reqCtx.Context(), accumulated, reqCtx)
				if err != nil {
					logrus.Error("Stream detection error:", err)
				}

				if result != nil && result.Matched && result.Action == types.ActionBlock {
					blockResult = result

					var shouldBlock bool
					switch policy {
					case "force_block":
						shouldBlock = true
					case "force_audit":
						shouldBlock = false
					default:
						shouldBlock = !auditOnly
					}

					if shouldBlock {
						blocked = true
						c.Writer.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"\\n\\n【检测到敏感数据，已终止生成】\"}},{\"finish_reason\":\"content_filter\"}]}\n\n"))
						c.Writer.Write([]byte("data: [DONE]\n\n"))
						c.Writer.Flush()
						logrus.Warn("Stream blocked for request:", reqCtx.ID, " reason:", result.Message, " policy:", policy)
						break
					} else {
						reqCtx.AddDetectionResult(*result)
					}
				}
			}
		}

		if isDone {
			break
		}

		if c.Request.Context().Err() != nil {
			break
		}
	}

	if !blocked {
		remaining := window.FlushAll()
		if remaining != "" {
			c.Writer.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"" + escapeJSON(remaining) + "\"}}]}\n\n"))
			c.Writer.Flush()
		}

		if blockResult == nil {
			c.Writer.Write([]byte("data: [DONE]\n\n"))
			c.Writer.Flush()
		}
	}

	reqCtx.StatusCode = resp.StatusCode
	reqCtx.Complete()
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}