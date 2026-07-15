package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"llm-audit-gateway/internal/audit"
	"llm-audit-gateway/internal/config"
	"llm-audit-gateway/internal/detector"
	"llm-audit-gateway/internal/pipeline"
	"llm-audit-gateway/internal/proxy"
	"llm-audit-gateway/internal/server"
	"llm-audit-gateway/internal/types"
)

var (
	configPath = flag.String("config", "configs/config.yaml", "Path to config file")
)

func main() {
	flag.Parse()

	logrus.SetLevel(logrus.InfoLevel)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	logrus.Info("Starting LLM Audit Gateway...")

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logrus.Fatal("Failed to load config:", err)
	}
	config.SetInstance(cfg)

	exemptionManager := detector.NewExemptionManager()
	if err := exemptionManager.LoadFromFile("configs/exemptions.yaml"); err != nil {
		logrus.Warn("Failed to load exemptions file:", err)
	}

	regexDetector, err := detector.NewRegexDetector(cfg, exemptionManager)
	if err != nil {
		logrus.Fatal("Failed to create regex detector:", err)
	}
	regexDetector.InitDefaultPurposeOverrides()

	piiDetector := detector.NewPIIDetector()
	semanticDetector := detector.NewSemanticDetector()

	detectionPipeline := pipeline.NewDetectionPipeline()

	if cfg.Detection.Tier1Enabled {
		detectionPipeline.AddDetector(regexDetector)
	}
	if cfg.Detection.Tier2Enabled {
		detectionPipeline.AddDetector(piiDetector)
	}
	if cfg.Detection.Tier3Enabled {
		detectionPipeline.AddDetector(semanticDetector)
	}

	auditLogger, err := audit.NewAuditLogger(cfg)
	if err != nil {
		logrus.Fatal("Failed to create audit logger:", err)
	}
	defer auditLogger.Close()

	proxyHandler, err := proxy.NewProxyHandler(cfg)
	if err != nil {
		logrus.Fatal("Failed to create proxy handler:", err)
	}

	proxyHandler.SetDetectionFunc(func(ctx context.Context, request *types.RequestContext) (*types.DetectionResult, error) {
		if cfg.Detection.ParallelDetection {
			return detectionPipeline.ExecuteParallel(ctx, request)
		}
		return detectionPipeline.Execute(ctx, request)
	})

	proxyHandler.SetStreamDetectFunc(func(ctx context.Context, accumulatedText string, request *types.RequestContext) (*types.DetectionResult, error) {
		return detectionPipeline.ExecuteStreamWithBuffer(ctx, accumulatedText, request)
	})

	proxyHandler.SetAuditFunc(auditLogger.Log)

	srv := server.NewServer(cfg, proxyHandler)

	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			logrus.Fatal("Server failed to start:", err)
		}
	}()

	adminSrv := server.NewAdminServer(cfg, detectionPipeline.GetStats(), exemptionManager, regexDetector, proxyHandler, auditLogger)

	go func() {
		if err := adminSrv.Start(); err != nil && err != http.ErrServerClosed {
			logrus.Error("Admin server failed:", err)
		}
	}()

	watcher, err := config.NewFileWatcher()
	if err != nil {
		logrus.Warn("Failed to create config watcher:", err)
	} else {
		if err := watcher.Watch(*configPath, func() {
			if err := config.ReloadConfig(*configPath); err != nil {
				logrus.Error("Failed to reload config:", err)
				return
			}
			newCfg := config.GetInstance()
			proxyHandler.UpdateConfig(newCfg)
			auditLogger.UpdateConfig(newCfg)
			if err := regexDetector.ReloadRules(newCfg); err != nil {
				logrus.Error("Failed to reload regex rules:", err)
			}
		}); err != nil {
			logrus.Warn("Failed to watch config file:", err)
		}
		defer watcher.Close()
	}

	exemptionWatcher, err := config.NewFileWatcher()
	if err != nil {
		logrus.Warn("Failed to create exemption watcher:", err)
	} else {
		if err := exemptionWatcher.Watch("configs/exemptions.yaml", func() {
			logrus.Info("Exemptions file changed, reloading...")
			if err := exemptionManager.LoadFromFile("configs/exemptions.yaml"); err != nil {
				logrus.Error("Failed to reload exemptions:", err)
			}
		}); err != nil {
			logrus.Warn("Failed to watch exemptions file:", err)
		}
		defer exemptionWatcher.Close()
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logrus.Info("Received shutdown signal")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Stop(ctx); err != nil {
		logrus.Error("Server shutdown failed:", err)
	}

	if err := adminSrv.Stop(ctx); err != nil {
		logrus.Error("Admin server shutdown failed:", err)
	}

	logrus.Info("Server shutdown complete")
}