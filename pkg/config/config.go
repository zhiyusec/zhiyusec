// Package config 提供配置管理功能
// 使用 Viper 库统一管理配置文件，支持 JSON/YAML/TOML 格式
package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config 主配置结构体
type Config struct {
	// 扫描配置
	Scan ScanConfig `mapstructure:"scan"`
	// 检测配置
	Detect DetectConfig `mapstructure:"detect"`
	// 报告配置
	Report ReportConfig `mapstructure:"report"`
	// 性能配置
	Performance PerformanceConfig `mapstructure:"performance"`
}

// ScanConfig 扫描相关配置
type ScanConfig struct {
	// 扫描路径列表
	Paths []string `mapstructure:"paths"`
	// 最大文件大小（字节），超过此大小的文件不扫描
	MaxFileSize int64 `mapstructure:"max_file_size"`
	// 是否扫描归档文件（zip、tar等）
	ScanArchives bool `mapstructure:"scan_archives"`
	// 是否跟随符号链接
	FollowSymlinks bool `mapstructure:"follow_symlinks"`
	// 黑名单路径（正则表达式）
	Blacklist []string `mapstructure:"blacklist"`
	// 白名单路径（正则表达式）
	Whitelist []string `mapstructure:"whitelist"`
	// 断点续扫文件路径
	CheckpointFile string `mapstructure:"checkpoint_file"`
	// 是否启用断点续扫
	EnableCheckpoint bool `mapstructure:"enable_checkpoint"`
}

// DetectConfig 检测相关配置
type DetectConfig struct {
	// 规则文件路径列表
	RuleFiles []string `mapstructure:"rule_files"`
	// 内置规则开关
	EnableBuiltinRules bool `mapstructure:"enable_builtin_rules"`
	// 熵值阈值（用于判断随机字符串）
	EntropyThreshold float64 `mapstructure:"entropy_threshold"`
	// 是否启用熵值检测
	EnableEntropyCheck bool `mapstructure:"enable_entropy_check"`
	// 是否启用弱加密检测
	EnableCryptoCheck bool `mapstructure:"enable_crypto_check"`
	// 自定义关键词列表
	CustomKeywords []string `mapstructure:"custom_keywords"`
	// 敏感信息类型开关
	EnabledTypes map[string]bool `mapstructure:"enabled_types"`
}

// ReportConfig 报告相关配置
type ReportConfig struct {
	// 输出格式：json, sarif, csv, html
	Formats []string `mapstructure:"formats"`
	// 输出目录
	OutputDir string `mapstructure:"output_dir"`
	// 输出文件名前缀
	FilePrefix string `mapstructure:"file_prefix"`
	// 是否包含超大文件列表
	IncludeLargeFiles bool `mapstructure:"include_large_files"`
	// 最小严重性级别：low, medium, high, critical
	MinSeverity string `mapstructure:"min_severity"`
	// 是否显示详细信息
	Verbose bool `mapstructure:"verbose"`
}

// PerformanceConfig 性能相关配置
type PerformanceConfig struct {
	// 最大并发扫描任务数
	MaxConcurrency int `mapstructure:"max_concurrency"`
	// 文件读取缓冲区大小
	BufferSize int `mapstructure:"buffer_size"`
	// 扫描超时时间
	ScanTimeout time.Duration `mapstructure:"scan_timeout"`
	// 是否启用进度条
	ShowProgress bool `mapstructure:"show_progress"`
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		Scan: ScanConfig{
			Paths:            []string{"."},
			MaxFileSize:      100 * 1024 * 1024, // 100MB
			ScanArchives:     true,
			FollowSymlinks:   false,
			Blacklist:        []string{},
			Whitelist:        []string{},
			CheckpointFile:   ".zhiyusec-checkpoint",
			EnableCheckpoint: false,
		},
		Detect: DetectConfig{
			RuleFiles:          []string{"configs/rules.yaml"},
			EnableBuiltinRules: true,
			EntropyThreshold:   4.5,
			EnableEntropyCheck: true,
			EnableCryptoCheck:  true,
			CustomKeywords:     []string{},
			EnabledTypes: map[string]bool{
				"api_key":      true,
				"password":     true,
				"private_key":  true,
				"token":        true,
				"certificate":  true,
				"database_url": true,
			},
		},
		Report: ReportConfig{
			Formats:           []string{"json"},
			OutputDir:         "reports",
			FilePrefix:        "zhiyusec-scan",
			IncludeLargeFiles: true,
			MinSeverity:       "low",
			Verbose:           false,
		},
		Performance: PerformanceConfig{
			MaxConcurrency: 10,
			BufferSize:     4096,
			ScanTimeout:    time.Hour * 2,
			ShowProgress:   true,
		},
	}
}

// LoadConfig 从文件加载配置
func LoadConfig(configFile string) (*Config, error) {
	// 设置默认配置
	cfg := DefaultConfig()

	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		// 搜索配置文件
		viper.SetConfigName("zhiyusec")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("./configs")
		viper.AddConfigPath("$HOME/.zhiyusec")
		viper.AddConfigPath("/etc/zhiyusec")
	}

	// 支持环境变量
	viper.SetEnvPrefix("ZHIYUSEC")
	viper.AutomaticEnv()

	// 尝试读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		// 如果配置文件不存在，使用默认配置
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("读取配置文件失败: %w", err)
		}
	}

	// 解析配置到结构体
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}

	// 验证配置
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}

	return cfg, nil
}

// Validate 验证配置的有效性
func (c *Config) Validate() error {
	// 验证扫描路径
	if len(c.Scan.Paths) == 0 {
		return fmt.Errorf("至少需要指定一个扫描路径")
	}

	// 验证文件大小限制
	if c.Scan.MaxFileSize <= 0 {
		return fmt.Errorf("最大文件大小必须大于0")
	}

	// 验证熵值阈值
	if c.Detect.EntropyThreshold < 0 || c.Detect.EntropyThreshold > 8 {
		return fmt.Errorf("熵值阈值必须在0-8之间")
	}

	// 验证报告格式
	validFormats := map[string]bool{"json": true, "sarif": true, "csv": true, "html": true}
	for _, format := range c.Report.Formats {
		if !validFormats[format] {
			return fmt.Errorf("不支持的报告格式: %s", format)
		}
	}

	// 验证严重性级别
	validSeverities := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if !validSeverities[c.Report.MinSeverity] {
		return fmt.Errorf("无效的严重性级别: %s", c.Report.MinSeverity)
	}

	// 验证并发数
	if c.Performance.MaxConcurrency <= 0 {
		return fmt.Errorf("最大并发数必须大于0")
	}

	return nil
}

// SaveConfig 保存配置到文件
func (c *Config) SaveConfig(configFile string) error {
	viper.SetConfigFile(configFile)
	return viper.WriteConfig()
}
