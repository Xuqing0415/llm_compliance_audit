package config

import (
	"os"
	"sync"

	"github.com/goccy/go-yaml"
	"github.com/sirupsen/logrus"
)

type RegexRule struct {
	Name       string   `yaml:"name" validate:"required"`
	Pattern    string   `yaml:"pattern" validate:"required"`
	Category   string   `yaml:"category"`
	Severity   string   `yaml:"severity"`
	Action     string   `yaml:"action"`
	Description string  `yaml:"description"`
}

type UpstreamConfig struct {
	URL                string            `yaml:"url" validate:"required"`
	Timeout            int               `yaml:"timeout"`
	MaxConnections     int               `yaml:"max_connections"`
	RequestHeaders     map[string]string `yaml:"request_headers"`
}

type ServerConfig struct {
	Host              string `yaml:"host"`
	Port              int    `yaml:"port"`
	AdminPort         int    `yaml:"admin_port"`
	ReadTimeout       int    `yaml:"read_timeout"`
	WriteTimeout      int    `yaml:"write_timeout"`
	MaxRequestBodySize int   `yaml:"max_request_body_size"`
}

type AuditConfig struct {
	Enabled              bool   `yaml:"enabled"`
	StorageType          string `yaml:"storage_type"`
	KafkaBrokers         []string `yaml:"kafka_brokers"`
	KafkaTopic           string `yaml:"kafka_topic"`
	ClickHouseDSN        string `yaml:"clickhouse_dsn"`
	OSSBucket            string `yaml:"oss_bucket"`
	LogRetentionDays     int    `yaml:"log_retention_days"`
	MaxDiskUsagePercent  int    `yaml:"max_disk_usage_percent"`
	MaxLogFileSizeMB     int    `yaml:"max_log_file_size_mb"`
	AuditSamplingRate    float64 `yaml:"audit_sampling_rate"`
}

type StreamConfig struct {
	WindowMaxSize      int `yaml:"window_max_size"`
	WindowFlushThreshold int `yaml:"window_flush_threshold"`
	MaxDelayMs         int `yaml:"max_delay_ms"`
}

type ExecutionPolicy struct {
	Name         string   `yaml:"name"`
	HeaderKey    string   `yaml:"header_key"`
	HeaderValues []string `yaml:"header_values"`
	Mode         string   `yaml:"mode"`
	Priority     int      `yaml:"priority"`
}

type PathPurposeMapping struct {
	Pattern string `yaml:"pattern"`
	Purpose string `yaml:"purpose"`
}

type PolicyGuardConfig struct {
	AutoEnableBlock      bool `yaml:"auto_enable_block"`
	MinSamplesForAuto    int  `yaml:"min_samples_for_auto"`
	HighRiskRuleNames    []string `yaml:"high_risk_rule_names"`
}

type DetectionConfig struct {
	Tier1Enabled        bool                  `yaml:"tier1_enabled"`
	Tier2Enabled        bool                  `yaml:"tier2_enabled"`
	Tier3Enabled        bool                  `yaml:"tier3_enabled"`
	RegexRules          []RegexRule           `yaml:"regex_rules"`
	ParallelDetection   bool                  `yaml:"parallel_detection"`
	FailOpen            bool                  `yaml:"fail_open"`
	AuditOnlyMode       bool                  `yaml:"audit_only_mode"`
	Stream              StreamConfig          `yaml:"stream"`
	MaxDetectionLength  int                   `yaml:"max_detection_length"`
	ExecutionPolicies   []ExecutionPolicy     `yaml:"execution_policies"`
	ExportBatchThreshold int                  `yaml:"export_batch_threshold"`
	PolicyGuard         PolicyGuardConfig     `yaml:"policy_guard"`
	PathPurposeMappings []PathPurposeMapping  `yaml:"path_purpose_mappings"`
}

type MonitoringConfig struct {
	Enabled       bool   `yaml:"enabled"`
	MetricsPort   int    `yaml:"metrics_port"`
	PrometheusURL string `yaml:"prometheus_url"`
}

type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Upstream   UpstreamConfig   `yaml:"upstream"`
	Audit      AuditConfig      `yaml:"audit"`
	Detection  DetectionConfig  `yaml:"detection"`
	Monitoring MonitoringConfig `yaml:"monitoring"`
}

var (
	instance *Config
	once     sync.Once
	mu       sync.RWMutex
)

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func GetInstance() *Config {
	mu.RLock()
	defer mu.RUnlock()
	return instance
}

func SetInstance(cfg *Config) {
	mu.Lock()
	defer mu.Unlock()
	instance = cfg
}

func ReloadConfig(path string) error {
	newConfig, err := LoadConfig(path)
	if err != nil {
		logrus.Error("Failed to reload config:", err)
		return err
	}

	SetInstance(newConfig)
	logrus.Info("Config reloaded successfully")
	return nil
}