// 示例：如何在 Go 程序中使用 zhiyusec-leaks
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/zhiyusec/zhiyusec-leaks/pkg/config"
	"github.com/zhiyusec/zhiyusec-leaks/pkg/runner"
)

func main() {
	// 示例 1：使用默认配置扫描
	example1()

	// 示例 2：使用自定义配置扫描
	example2()

	// 示例 3：程序化构建配置
	example3()
}

// 示例 1：使用默认配置扫描
func example1() {
	fmt.Println("=== 示例 1: 使用默认配置扫描 ===\n")

	// 加载默认配置
	cfg := config.DefaultConfig()
	cfg.Scan.Paths = []string{"."}
	cfg.Performance.ShowProgress = false // 示例中禁用进度条

	// 创建运行器
	r, err := runner.NewRunner(cfg)
	if err != nil {
		log.Fatalf("创建运行器失败: %v", err)
	}

	// 运行扫描
	ctx := context.Background()
	if err := r.Run(ctx); err != nil {
		log.Fatalf("扫描失败: %v", err)
	}

	// 获取结果
	result := r.GetResult()
	fmt.Printf("扫描完成，发现 %d 个敏感信息\n\n", len(result.Findings))
}

// 示例 2：使用自定义配置扫描
func example2() {
	fmt.Println("=== 示例 2: 使用自定义配置文件扫描 ===\n")

	// 从配置文件加载
	cfg, err := config.LoadConfig("configs/zhiyusec.yaml")
	if err != nil {
		// 如果配置文件不存在，使用默认配置
		cfg = config.DefaultConfig()
	}

	// 覆盖部分配置
	cfg.Scan.Paths = []string{"./example"}
	cfg.Report.Formats = []string{"json", "html"}
	cfg.Performance.ShowProgress = false

	// 创建并运行扫描
	r, err := runner.NewRunner(cfg)
	if err != nil {
		log.Fatalf("创建运行器失败: %v", err)
	}

	ctx := context.Background()
	if err := r.Run(ctx); err != nil {
		log.Fatalf("扫描失败: %v", err)
	}

	fmt.Println("扫描完成\n")
}

// 示例 3：程序化构建配置
func example3() {
	fmt.Println("=== 示例 3: 程序化构建配置 ===\n")

	// 创建自定义配置
	cfg := &config.Config{
		Scan: config.ScanConfig{
			Paths:          []string{"."},
			MaxFileSize:    50 * 1024 * 1024, // 50MB
			ScanArchives:   true,
			FollowSymlinks: false,
			Blacklist: []string{
				"node_modules",
				"\\.git",
				"vendor",
			},
		},
		Detect: config.DetectConfig{
			RuleFiles:          []string{},
			EnableBuiltinRules: true,
			EntropyThreshold:   4.5,
			EnableEntropyCheck: true,
			EnableCryptoCheck:  false,
			EnabledTypes: map[string]bool{
				"api_key":     true,
				"password":    true,
				"private_key": true,
				"token":       true,
			},
		},
		Report: config.ReportConfig{
			Formats:           []string{"json"},
			OutputDir:         "example-reports",
			FilePrefix:        "example-scan",
			IncludeLargeFiles: true,
			MinSeverity:       "medium", // 只报告中危及以上
			Verbose:           false,
		},
		Performance: config.PerformanceConfig{
			MaxConcurrency: 5,
			BufferSize:     4096,
			ShowProgress:   false,
		},
	}

	// 验证配置
	if err := cfg.Validate(); err != nil {
		log.Fatalf("配置验证失败: %v", err)
	}

	// 创建并运行扫描
	r, err := runner.NewRunner(cfg)
	if err != nil {
		log.Fatalf("创建运行器失败: %v", err)
	}

	ctx := context.Background()
	if err := r.Run(ctx); err != nil {
		log.Fatalf("扫描失败: %v", err)
	}

	// 分析结果
	result := r.GetResult()
	fmt.Printf("扫描统计:\n")
	fmt.Printf("- 扫描文件: %d\n", result.TotalFiles)
	fmt.Printf("- 发现总数: %d\n", len(result.Findings))
	fmt.Printf("- 扫描耗时: %v\n", result.Duration)

	// 按严重性统计
	fmt.Println("\n严重性分布:")
	for severity, count := range result.Statistics.BySeverity {
		if count > 0 {
			fmt.Printf("- %s: %d\n", severity, count)
		}
	}

	fmt.Println()
}
