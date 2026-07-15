package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"llm-audit-gateway/internal/audit"
	"llm-audit-gateway/internal/config"
	"llm-audit-gateway/internal/detector"
	"llm-audit-gateway/internal/pipeline"
	"llm-audit-gateway/internal/proxy"
	"llm-audit-gateway/internal/types"
)

type AdminServer struct {
	engine        *gin.Engine
	httpServer    *http.Server
	stats         *pipeline.StatsCollector
	exemption     *detector.ExemptionManager
	regexDetector *detector.RegexDetector
	proxyHandler  *proxy.ProxyHandler
	auditLogger   *audit.AuditLogger
}

func NewAdminServer(cfg *config.Config, stats *pipeline.StatsCollector, exemption *detector.ExemptionManager, regexDetector *detector.RegexDetector, proxyHandler *proxy.ProxyHandler, auditLogger *audit.AuditLogger) *AdminServer {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()

	engine.Use(gin.Logger())
	engine.Use(gin.Recovery())

	as := &AdminServer{
		engine:        engine,
		stats:         stats,
		exemption:     exemption,
		regexDetector: regexDetector,
		proxyHandler:  proxyHandler,
		auditLogger:   auditLogger,
	}

	as.setupRoutes()

	adminPort := cfg.Server.AdminPort
	if adminPort == 0 {
		adminPort = 9090
	}

	httpServer := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", cfg.Server.Host, adminPort),
		Handler:        engine,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1024 * 1024,
	}

	as.httpServer = httpServer
	return as
}

func (as *AdminServer) setupRoutes() {
	as.engine.POST("/admin/whitelist", as.handleWhitelist)
	as.engine.POST("/admin/rules/toggle", as.handleRuleToggle)
	as.engine.GET("/admin/stats", as.handleStats)
	as.engine.POST("/admin/exemptions/reload", as.handleExemptionsReload)
	as.engine.GET("/admin/exemptions", as.handleGetExemptions)
	as.engine.POST("/admin/bypass", as.handleBypass)
	as.engine.GET("/admin/bypass", as.handleGetBypass)
	as.engine.POST("/admin/policy/active", as.handlePolicyActive)
	as.engine.GET("/admin/policy/active", as.handleGetPolicyActive)
	as.engine.GET("/admin/audit/trace", as.handleAuditTrace)
}

func (as *AdminServer) handleWhitelist(c *gin.Context) {
	var request struct {
		RuleName string `json:"rule_name" binding:"required"`
		Keyword  string `json:"keyword" binding:"required"`
		Action   string `json:"action" binding:"required,oneof=add remove"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request", "details": err.Error()})
		return
	}

	if as.exemption == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Exemption manager not initialized"})
		return
	}

	switch request.Action {
	case "add":
		as.exemption.AddKeyword(request.RuleName, request.Keyword)
		c.JSON(http.StatusOK, gin.H{
			"status":     "success",
			"rule_name":  request.RuleName,
			"keyword":    request.Keyword,
			"action":     "added",
		})
	case "remove":
		as.exemption.RemoveKeyword(request.RuleName, request.Keyword)
		c.JSON(http.StatusOK, gin.H{
			"status":     "success",
			"rule_name":  request.RuleName,
			"keyword":    request.Keyword,
			"action":     "removed",
		})
	}
}

func (as *AdminServer) handleRuleToggle(c *gin.Context) {
	var request struct {
		RuleName string `json:"rule_name" binding:"required"`
		Enable   bool   `json:"enable" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request", "details": err.Error()})
		return
	}

	if as.regexDetector == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Regex detector not initialized"})
		return
	}

	as.regexDetector.ToggleRule(request.RuleName, request.Enable)

	c.JSON(http.StatusOK, gin.H{
		"status":    "success",
		"rule_name": request.RuleName,
		"enabled":   request.Enable,
	})
}

func (as *AdminServer) handleStats(c *gin.Context) {
	if as.stats == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Stats collector not initialized"})
		return
	}

	detectorsStats := as.stats.GetAllStats()
	statsResponse := make(map[string]interface{})

	for name, stats := range detectorsStats {
		statsResponse[name] = map[string]interface{}{
			"total_count":    stats.TotalCount,
			"match_count":    stats.MatchCount,
			"avg_latency_ms": as.stats.GetAverageLatency(name).Milliseconds(),
			"p99_latency_ms": as.stats.GetP99Latency(name).Milliseconds(),
			"max_latency_ms": stats.MaxLatency.Milliseconds(),
			"min_latency_ms": stats.MinLatency.Milliseconds(),
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"uptime_seconds":   int(as.stats.GetUptime().Seconds()),
		"total_requests":   as.stats.GetTotalRequests(),
		"blocked_requests": as.stats.GetBlockedRequests(),
		"allowed_requests": as.stats.GetAllowedRequests(),
		"detectors":        statsResponse,
	})
}

func (as *AdminServer) handleExemptionsReload(c *gin.Context) {
	if as.exemption == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Exemption manager not initialized"})
		return
	}

	if err := as.exemption.LoadFromFile("configs/exemptions.yaml"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reload exemptions", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Exemptions reloaded"})
}

func (as *AdminServer) handleGetExemptions(c *gin.Context) {
	if as.exemption == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Exemption manager not initialized"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"exemptions":      as.exemption.GetAllExemptions(),
		"false_positives": as.exemption.GetAllFalsePositives(),
	})
}

func (as *AdminServer) handleBypass(c *gin.Context) {
	var request struct {
		Enable bool `json:"enable" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request", "details": err.Error()})
		return
	}

	if as.proxyHandler == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Proxy handler not initialized"})
		return
	}

	as.proxyHandler.SetBypassMode(request.Enable)

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"bypass":  request.Enable,
		"message": map[bool]string{true: "Bypass mode enabled: all detection skipped", false: "Bypass mode disabled: detection resumed"}[request.Enable],
	})
}

func (as *AdminServer) handleGetBypass(c *gin.Context) {
	if as.proxyHandler == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Proxy handler not initialized"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"bypass": as.proxyHandler.IsBypassMode(),
	})
}

func (as *AdminServer) handlePolicyActive(c *gin.Context) {
	var request struct {
		Set string `json:"set" binding:"required,oneof=default fallback-audit force-block"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request", "details": err.Error()})
		return
	}

	types.SetActivePolicy(request.Set)

	switch request.Set {
	case "fallback-audit":
		if as.proxyHandler != nil {
			logrus.Warn("Fallback audit policy activated: all high-risk groups switched to audit-only mode")
		}
	case "force-block":
		logrus.Warn("Force-block policy activated: all matched rules will block")
	case "default":
		logrus.Info("Default policy restored")
	}

	c.JSON(http.StatusOK, gin.H{
		"status":       "success",
		"active_policy": types.GetActivePolicy(),
		"message": map[string]string{
			"default":         "Default policy restored: follows execution_policies config",
			"fallback-audit":  "Fallback audit policy activated: all policies behave as force_audit",
			"force-block":     "Force-block policy activated: all policies behave as force_block",
		}[request.Set],
	})
}

func (as *AdminServer) handleGetPolicyActive(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"active_policy": types.GetActivePolicy(),
	})
}

func (as *AdminServer) handleAuditTrace(c *gin.Context) {
	traceID := c.Query("trace_id")
	if traceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "trace_id is required"})
		return
	}

	if as.auditLogger == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Audit logger not initialized"})
		return
	}

	entry, err := as.auditLogger.QueryByTraceID(traceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query audit log", "details": err.Error()})
		return
	}

	if entry == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No audit record found for trace_id", "trace_id": traceID})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"trace_id":        entry.SessionID,
		"request_id":      entry.RequestID,
		"timestamp":       entry.Timestamp.Format(time.RFC3339),
		"client_ip":       entry.ClientIP,
		"final_severity":  string(entry.FinalSeverity),
		"sensitivity":     entry.Sensitivity,
		"action":          string(entry.Action),
		"triggered_rules": entry.TriggeredRules,
		"status_code":     entry.StatusCode,
		"detection_results": entry.DetectionResults,
		"duration_ms":     entry.Duration,
	})
}

func (as *AdminServer) Start() error {
	logrus.Info("Starting admin server on ", as.httpServer.Addr)
	return as.httpServer.ListenAndServe()
}

func (as *AdminServer) Stop(ctx context.Context) error {
	logrus.Info("Shutting down admin server...")
	return as.httpServer.Shutdown(ctx)
}