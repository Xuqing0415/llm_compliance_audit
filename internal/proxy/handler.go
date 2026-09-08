package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	proxy            *httputil.ReverseProxy
	upstreamURL      *url.URL
	config           *config.Config
	mu               sync.RWMutex
	detectionFunc    func(ctx context.Context, request *types.RequestContext) (*types.DetectionResult, error)
	streamDetectFunc func(ctx context.Context, accumulatedText string, request *types.RequestContext) (*types.DetectionResult, error)
	auditFunc        func(ctx context.Context, request *types.RequestContext) error
	bypassMode       bool
	bypassMu         sync.RWMutex
	streamHTTPClient *http.Client
}

// maxBufferedResponseBytes caps how much of a non-stream upstream response is
// buffered for response scanning. Long LLM answers travel over the streaming
// path and are never subject to this cap; only oversized non-stream bodies
// (rare in practice) hit the limit.
const maxBufferedResponseBytes = 64 << 20

var errBufferedResponseTooLarge = errors.New("buffered upstream response exceeded inspection limit")

func NewProxyHandler(cfg *config.Config) (*ProxyHandler, error) {
	upstreamURL, err := url.Parse(cfg.Upstream.URL)
	if err != nil {
		return nil, err
	}

	ph := &ProxyHandler{
		upstreamURL: upstreamURL,
		config:      cfg,
		streamHTTPClient: &http.Client{
			// No overall client timeout on purpose: LLM streams routinely run
			// for minutes. Cancellation is driven by the request context (the
			// client disconnecting cancels the upstream call).
			Transport: &http.Transport{
				MaxIdleConns:        cfg.Upstream.MaxConnections,
				MaxIdleConnsPerHost: cfg.Upstream.MaxConnections,
				IdleConnTimeout:     30 * time.Second,
			},
		},
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

	oldClient := ph.streamHTTPClient
	ph.streamHTTPClient = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        cfg.Upstream.MaxConnections,
			MaxIdleConnsPerHost: cfg.Upstream.MaxConnections,
			IdleConnTimeout:     30 * time.Second,
		},
	}
	if oldClient != nil {
		oldClient.CloseIdleConnections()
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

// joinUpstreamPath joins a configured upstream base path (e.g. "/v1") with the
// inbound request path. If the request already carries the base path as a
// prefix it is used as-is so that we never emit "/v1/v1/..." duplicates.
func joinUpstreamPath(basePath, reqPath string) string {
	if basePath == "" || basePath == "/" {
		return reqPath
	}
	basePath = strings.TrimSuffix(basePath, "/")
	if reqPath == basePath || strings.HasPrefix(reqPath, basePath+"/") {
		return reqPath
	}
	return basePath + reqPath
}

func isHopByHopHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
		"proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "host":
		return true
	}
	return false
}

// copyInboundHeaders copies client headers to the upstream request while
// stripping hop-by-hop headers and Accept-Encoding. Accept-Encoding is dropped
// so the http.Transport can negotiate/decompress the response transparently
// (the SSE parser expects plain text).
func copyInboundHeaders(dst http.Header, src map[string][]string) {
	for k, v := range src {
		if isHopByHopHeader(k) {
			continue
		}
		if strings.EqualFold(k, "Accept-Encoding") {
			continue
		}
		dst[k] = append([]string(nil), v...)
	}
}

// extractRequestPurpose derives the request purpose ONLY from server-side
// configuration and path heuristics. Client-supplied X-Request-Purpose /
// X-Flow-Type headers are deliberately ignored: honoring them would let any
// caller self-declare an "export" purpose, downgrading BLOCK rules to ALERT
// and switching off response scanning.
func (ph *ProxyHandler) extractRequestPurpose(c *gin.Context) string {
	ph.mu.RLock()
	mappings := ph.config.Detection.PathPurposeMappings
	ph.mu.RUnlock()

	path := c.Request.URL.Path
	for _, mapping := range mappings {
		if strings.Contains(path, mapping.Pattern) {
			return mapping.Purpose
		}
	}

	if strings.Contains(path, "/export") {
		return "export"
	}

	if strings.Contains(path, "/codegen") ||
		strings.Contains(path, "/code") {
		return "codegen"
	}

	if strings.Contains(path, "/api/chat/completions") {
		return "chat"
	}

	return ""
}

func isExportLikePurpose(purpose string) bool {
	return purpose == "export" || purpose == "export-batch"
}

func (ph *ProxyHandler) shouldUseStreaming(c *gin.Context, purpose string) bool {
	if purpose == "export-batch" ||
		strings.Contains(c.Request.URL.Path, "/batch") ||
		strings.Contains(c.Request.URL.Path, "/download") {
		return false
	}

	if purpose == "export" {
		return strings.Contains(c.GetHeader("Accept"), "text/event-stream")
	}

	return strings.Contains(c.GetHeader("Accept"), "text/event-stream") ||
		strings.Contains(c.GetHeader("Content-Type"), "text/event-stream") ||
		strings.Contains(c.Request.URL.Path, "/stream")
}

func (ph *ProxyHandler) extractExecutionPolicy(c *gin.Context, purpose string) string {
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

		matched := false
		for _, allowedValue := range policy.HeaderValues {
			if strings.EqualFold(headerValue, allowedValue) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		// A client-supplied "force_audit" policy is only honored when the
		// server-derived purpose is export-like. Otherwise any caller could
		// attach X-Export-Scope: low-risk to an ordinary chat request and
		// neutralize blocking.
		if policy.Mode == "force_audit" && !isExportLikePurpose(purpose) {
			continue
		}

		return policy.Mode
	}

	return ""
}

func (ph *ProxyHandler) director(req *http.Request) {
	ph.mu.RLock()
	upstream := *ph.upstreamURL
	requestHeaders := ph.config.Upstream.RequestHeaders
	ph.mu.RUnlock()

	req.URL.Scheme = upstream.Scheme
	req.URL.Host = upstream.Host
	req.URL.Path = joinUpstreamPath(upstream.Path, req.URL.Path)
	req.URL.RawPath = ""

	req.Header.Set("Host", upstream.Host)

	for k, v := range requestHeaders {
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

func (ph *ProxyHandler) shouldBlock(reqCtx *types.RequestContext, action types.Action) bool {
	switch reqCtx.ExecutionPolicy {
	case "force_block":
		return action == types.ActionBlock
	case "force_audit":
		return false
	}

	ph.mu.RLock()
	auditOnly := ph.config.Detection.AuditOnlyMode
	ph.mu.RUnlock()

	return action == types.ActionBlock && !auditOnly
}

// bufferedResponseWriter captures an upstream response without writing a single
// byte through to the client. Response scanning can therefore veto the reply
// (e.g. return 403) before any sensitive content is released.
type bufferedResponseWriter struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	overflow bool
	limit    int
}

func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{header: make(http.Header), limit: maxBufferedResponseBytes}
}

func (b *bufferedResponseWriter) Header() http.Header {
	return b.header
}

func (b *bufferedResponseWriter) Write(p []byte) (int, error) {
	if !b.overflow && b.body.Len()+len(p) > b.limit {
		b.overflow = true
		return 0, errBufferedResponseTooLarge
	}
	return b.body.Write(p)
}

func (b *bufferedResponseWriter) WriteHeader(statusCode int) {
	if b.status == 0 {
		b.status = statusCode
	}
}

func (b *bufferedResponseWriter) Status() int {
	if b.status == 0 {
		return http.StatusOK
	}
	return b.status
}

func (b *bufferedResponseWriter) BodyString() string {
	return b.body.String()
}

func (b *bufferedResponseWriter) Overflow() bool {
	return b.overflow
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
	reqCtx.ExecutionPolicy = ph.extractExecutionPolicy(c, reqCtx.RequestPurpose)
	reqCtx.ResponseScanningEnabled = !isExportLikePurpose(reqCtx.RequestPurpose)

	ph.mu.RLock()
	failOpen := ph.config.Detection.FailOpen
	maxDetectionLen := ph.config.Detection.MaxDetectionLength
	maxBodySize := ph.config.Server.MaxRequestBodySize
	ph.mu.RUnlock()

	// Enforce the configured request body limit on the body itself (it used to
	// be stuffed into MaxHeaderBytes, which limited headers, not the body).
	var bodyReader io.Reader = c.Request.Body
	if maxBodySize > 0 {
		bodyReader = http.MaxBytesReader(c.Writer, c.Request.Body, int64(maxBodySize))
	}
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "Request body too large"})
			return
		}
		logrus.Error("Failed to read request body:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
		return
	}
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	fullBody := string(body)

	h := sha256.New()
	h.Write(body)
	reqCtx.RequestBodyHash = hex.EncodeToString(h.Sum(nil))

	if maxDetectionLen <= 0 {
		maxDetectionLen = 2000
	}
	reqCtx.RequestBody = fullBody
	if len(fullBody) > maxDetectionLen {
		// Detection sees a bounded prefix; the upstream still receives the full body.
		reqCtx.RequestBody = fullBody[:maxDetectionLen]
	}

	reqCtx.IsStream = ph.shouldUseStreaming(c, reqCtx.RequestPurpose)

	if !ph.IsBypassMode() && ph.detectionFunc != nil {
		result, err := ph.detectionFunc(reqCtx.Context(), reqCtx)
		if err != nil {
			logrus.Error("Detection error:", err)
			if !failOpen {
				c.JSON(http.StatusForbidden, gin.H{"error": "Detection failed", "action": "BLOCK"})
				return
			}
		}

		if result != nil && result.Matched {
			reqCtx.AddDetectionResult(*result)
			if ph.shouldBlock(reqCtx, result.Action) {
				reqCtx.SetAction(types.ActionBlock)
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

			reqCtx.SetAction(result.Action)
		} else {
			reqCtx.SetAction(types.ActionAllow)
		}
	} else {
		reqCtx.SetAction(types.ActionAllow)
	}

	if reqCtx.IsStream {
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
	rp := ph.proxy
	ph.mu.RUnlock()

	// Admin bypass and export-style purposes are intentionally not response-
	// scanned; stream those straight through instead of buffering a potentially
	// huge body in memory for a scan that is disabled anyway.
	if ph.IsBypassMode() || !reqCtx.ResponseScanningEnabled {
		rp.ServeHTTP(c.Writer, c.Request)
		reqCtx.StatusCode = c.Writer.Status()
		reqCtx.Complete()
		return
	}

	// Buffer the upstream response in full before writing anything to the
	// client: the response detector must be able to veto the reply. Streaming
	// the body through first would release sensitive content before a 403.
	buffered := newBufferedResponseWriter()
	rp.ServeHTTP(buffered, c.Request)
	if buffered.Overflow() {
		// Never release a response we could not fully inspect. The client gets
		// an error instead of an unvetted (possibly sensitive) body.
		reqCtx.StatusCode = http.StatusBadGateway
		reqCtx.Complete()
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": "Upstream response too large to inspect"})
		return
	}
	ph.writeBufferedResponse(c, reqCtx, buffered.Status(), buffered.Header(), buffered.BodyString())
}

func (ph *ProxyHandler) writeBufferedResponse(c *gin.Context, reqCtx *types.RequestContext, statusCode int, headers http.Header, body string) {
	reqCtx.StatusCode = statusCode
	reqCtx.ResponseHeaders = headers.Clone()
	reqCtx.ResponseBody = body

	if ph.checkAndBlockResponse(c, reqCtx) {
		reqCtx.Complete()
		return
	}

	for k, v := range headers {
		c.Writer.Header()[k] = v
	}
	c.Writer.WriteHeader(statusCode)
	if body != "" {
		_, _ = c.Writer.Write([]byte(body))
	}
	reqCtx.Complete()
}

// checkAndBlockResponse runs the response detector over the already-buffered
// response body. It returns true (and writes a 403) when the response must be
// withheld. Nothing has been written to the client yet when this is called.
func (ph *ProxyHandler) checkAndBlockResponse(c *gin.Context, reqCtx *types.RequestContext) bool {
	if ph.IsBypassMode() || !reqCtx.ResponseScanningEnabled || ph.detectionFunc == nil || reqCtx.ResponseBody == "" {
		return false
	}

	respCtx := &types.RequestContext{
		RequestBody:     reqCtx.ResponseBody,
		RequestPurpose:  reqCtx.RequestPurpose,
		ExecutionPolicy: reqCtx.ExecutionPolicy,
	}
	result, err := ph.detectionFunc(reqCtx.Context(), respCtx)
	if err != nil {
		logrus.Error("Response detection error:", err)
		return false
	}

	if result == nil || !result.Matched {
		return false
	}

	reqCtx.AddDetectionResult(*result)
	if !ph.shouldBlock(reqCtx, result.Action) {
		return false
	}

	reqCtx.SetAction(types.ActionBlock)
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error":        "Response blocked by audit gateway",
		"reason":       result.Message,
		"category":     result.Category,
		"severity":     result.Severity,
		"detection_id": reqCtx.ID,
		"policy":       reqCtx.ExecutionPolicy,
	})
	return true
}

func (ph *ProxyHandler) handleStream(c *gin.Context, reqCtx *types.RequestContext) {
	ph.mu.RLock()
	upstreamURL := *ph.upstreamURL
	streamCfg := ph.config.Detection.Stream
	auditOnly := ph.config.Detection.AuditOnlyMode
	policy := reqCtx.ExecutionPolicy
	client := ph.streamHTTPClient
	extraHeaders := ph.config.Upstream.RequestHeaders
	ph.mu.RUnlock()

	// Forward the FULL original request body. reqCtx.RequestBody may be a
	// truncated detection prefix and must never be what is sent upstream.
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logrus.Error("Failed to read request body for streaming:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
		return
	}

	u := upstreamURL
	u.Path = joinUpstreamPath(u.Path, reqCtx.Path)
	upstreamReq, err := http.NewRequestWithContext(c.Request.Context(), reqCtx.Method, u.String(), bytes.NewReader(body))
	if err != nil {
		logrus.Error("Failed to create upstream request:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create upstream request"})
		return
	}

	copyInboundHeaders(upstreamReq.Header, reqCtx.RequestHeaders)
	for k, v := range extraHeaders {
		upstreamReq.Header.Set(k, v)
	}

	resp, err := client.Do(upstreamReq)
	if err != nil {
		logrus.Error("Failed to connect to upstream:", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to connect to upstream"})
		return
	}
	defer resp.Body.Close()

	// Passthrough remains intentionally raw only for an admin-enabled bypass,
	// or for export purposes derived server-side.
	if ph.IsBypassMode() || !reqCtx.ResponseScanningEnabled {
		for k, v := range resp.Header {
			c.Writer.Header()[k] = v
		}
		c.Writer.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(c.Writer, resp.Body)
		c.Writer.Flush()
		reqCtx.StatusCode = resp.StatusCode
		reqCtx.Complete()
		return
	}

	peekBuffer := make([]byte, 1024)
	peekN, peekErr := resp.Body.Read(peekBuffer)
	if peekErr != nil && peekErr != io.EOF {
		logrus.Error("Failed to peek response body:", peekErr)
		reqCtx.StatusCode = resp.StatusCode
		ph.writeBufferedResponse(c, reqCtx, resp.StatusCode, resp.Header, "")
		return
	}

	isSSEFormat := strings.HasPrefix(strings.TrimSpace(string(peekBuffer[:peekN])), "data:")
	if !isSSEFormat {
		// Upstream answered with a non-SSE body even though the client asked
		// for a stream. Buffer it and run response scanning before releasing
		// anything (same guarantee as handleNormal).
		rest, readErr := io.ReadAll(&peekReader{ReadCloser: resp.Body, buf: peekBuffer[:peekN]})
		if readErr != nil {
			logrus.Error("Failed to read non-SSE response body:", readErr)
		}
		ph.writeBufferedResponse(c, reqCtx, resp.StatusCode, resp.Header, string(rest))
		return
	}

	for k, v := range resp.Header {
		c.Writer.Header()[k] = v
	}
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	// The upstream response carries a Content-Length header, which conflicts
	// with the chunked Transfer-Encoding we set for streaming. Drop it so the
	// client does not truncate the body at the original length.
	c.Writer.Header().Del("Content-Length")
	c.Writer.Header().Del("Content-Encoding")
	c.Writer.WriteHeader(resp.StatusCode)
	c.Writer.Flush()

	resp.Body = &peekReader{ReadCloser: resp.Body, buf: peekBuffer[:peekN]}

	parser := stream.NewSSEParser(resp.Body)
	window := stream.NewSlidingWindow(streamCfg.WindowMaxSize, streamCfg.WindowFlushThreshold)

	lastFlushTime := time.Now()
	blocked := false

	// flushBuffered detects the buffered window BEFORE any of its content is
	// written to the client, then releases the content only when it is clean.
	// It returns true when the stream must be terminated because of a block.
	flushBuffered := func(final bool) bool {
		for {
			unflushed := window.UnflushedSize()
			if unflushed == 0 {
				return false
			}

			now := time.Now()
			if !final && unflushed < streamCfg.WindowFlushThreshold &&
				now.Sub(lastFlushTime).Milliseconds() < int64(streamCfg.MaxDelayMs) {
				return false
			}

			if ph.streamDetectFunc != nil {
				result, err := ph.streamDetectFunc(reqCtx.Context(), window.GetCurrentBuffer(), reqCtx)
				if err != nil {
					logrus.Error("Stream detection error:", err)
				}

				if result != nil && result.Matched && result.Action == types.ActionBlock {
					var shouldBlock bool
					switch policy {
					case "force_block":
						shouldBlock = true
					case "force_audit":
						shouldBlock = false
					default:
						shouldBlock = !auditOnly
					}

					alreadyRecorded := false
					for _, dr := range reqCtx.DetectionResults {
						if dr.HitRuleID == result.HitRuleID && dr.MatchedText == result.MatchedText && dr.Action == result.Action {
							alreadyRecorded = true
							break
						}
					}
					if !alreadyRecorded {
						reqCtx.AddDetectionResult(*result)
					}

					if shouldBlock {
						blocked = true
						reqCtx.SetAction(types.ActionBlock)
						c.Writer.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"\\n\\n【检测到敏感数据，已终止生成】\"}},{\"finish_reason\":\"content_filter\"}]}\n\n"))
						c.Writer.Write([]byte("data: [DONE]\n\n"))
						c.Writer.Flush()
						logrus.Warn("Stream blocked for request:", reqCtx.ID, " reason:", result.Message, " policy:", policy)
						return true
					}
				}
			}

			var chunk string
			if unflushed >= streamCfg.WindowFlushThreshold {
				chunk, _ = window.Flush()
			} else {
				chunk = window.FlushAll()
			}
			if chunk != "" {
				c.Writer.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"" + escapeJSON(chunk) + "\"}}]}\n\n"))
				c.Writer.Flush()
				lastFlushTime = time.Now()
			}

			if final {
				return false
			}
		}
	}

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

		if flushBuffered(isDone) {
			break
		}

		if isDone {
			break
		}

		if c.Request.Context().Err() != nil {
			break
		}
	}

	if !blocked {
		flushBuffered(true)
		c.Writer.Write([]byte("data: [DONE]\n\n"))
		c.Writer.Flush()
	}

	reqCtx.StatusCode = resp.StatusCode
	reqCtx.Complete()
}

func escapeJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return s
	}
	// json.Marshal returns a quoted string like "content", strip the surrounding quotes
	raw := string(b)
	if len(raw) >= 2 {
		return raw[1 : len(raw)-1]
	}
	return raw
}
