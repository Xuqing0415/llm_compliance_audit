package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"llm-audit-gateway/internal/config"
	"llm-audit-gateway/internal/proxy"
)

type Server struct {
	engine      *gin.Engine
	httpServer  *http.Server
	metricsAddr string
}

func NewServer(cfg *config.Config, proxyHandler *proxy.ProxyHandler) *Server {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()

	engine.Use(gin.Logger())
	engine.Use(gin.Recovery())

	engine.POST("/v1/chat/completions", func(c *gin.Context) {
		proxyHandler.ServeHTTP(c)
	})

	engine.POST("/v1/completions", func(c *gin.Context) {
		proxyHandler.ServeHTTP(c)
	})

	// NoRoute proxies every other path to the upstream without registering a
	// catch-all route, which would conflict with the static /v1/* routes above
	// and panic gin at startup.
	engine.NoRoute(func(c *gin.Context) {
		proxyHandler.ServeHTTP(c)
	})

	if cfg.Monitoring.Enabled {
		engine.GET("/metrics", gin.WrapH(promhttp.Handler()))
	}

	engine.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	engine.GET("/ready", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	httpServer := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      engine,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: 0, // streaming LLM responses routinely exceed 30s; a write
		// deadline would abort long generations mid-stream.
		// max_request_body_size is enforced on the body in the proxy handler
		// (http.MaxBytesReader), not via MaxHeaderBytes.
	}

	return &Server{
		engine:     engine,
		httpServer: httpServer,
	}
}

func (s *Server) Start() error {
	logrus.Info("Starting server on ", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

func (s *Server) Stop(ctx context.Context) error {
	logrus.Info("Shutting down server...")
	return s.httpServer.Shutdown(ctx)
}
