// zhiyusec-leaks 主程序入口
// 企业级敏感信息泄漏检测工具
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/zhiyusec/zhiyusec-leaks/pkg/config"
	"github.com/zhiyusec/zhiyusec-leaks/pkg/runner"
)

var (
	// 版本信息
	version = "1.0.0"

	// 命令行参数
	configFile     string
	scanPaths      []string
	outputDir      string
	reportFormats  []string
	maxConcurrency int
	maxFileSize    int64
	verbose        bool
	noProgress     bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "zhiyusec-leaks [flags] [paths...]",
		Short: "知御安全 - 敏感信息泄漏检测工具",
		Long: `
╔══════════════════════════════════════════════════════════════╗
║  🛡️  知御安全 zhiyusec-leaks                                  ║
║  企业级敏感信息泄漏检测扫描器                                  ║
║                                                              ║
║  功能特性:                                                   ║
║  • 多规则检测引擎 (API密钥、密码、证书等)                     ║
║  • 高性能并发扫描                                            ║
║  • 智能熵值分析                                              ║
║  • 多格式报告输出 (JSON/CSV/HTML/SARIF)                     ║
║  • 归档文件自动解压扫描                                       ║
║  • 黑白名单过滤                                              ║
║                                                              ║
║  © 2025 zhiyusec 知御安全个人实验室                          ║
╚══════════════════════════════════════════════════════════════╝
`,
		Example: `  # 扫描当前目录
  zhiyusec-leaks .

  # 扫描多个路径
  zhiyusec-leaks /path/to/dir1 /path/to/dir2

  # 使用配置文件
  zhiyusec-leaks -c config.yaml

  # 指定输出目录和格式
  zhiyusec-leaks -o reports -f json,html .

  # 调整并发数和文件大小限制
  zhiyusec-leaks --max-concurrency 20 --max-file-size 200000000 .`,
		Version: version,
		RunE:    run,
	}

	// 定义命令行参数
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "", "配置文件路径")
	rootCmd.Flags().StringSliceVarP(&scanPaths, "paths", "p", []string{}, "扫描路径列表")
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", "reports", "报告输出目录")
	rootCmd.Flags().StringSliceVarP(&reportFormats, "format", "f", []string{"json"}, "报告格式 (json,csv,html,sarif)")
	rootCmd.Flags().IntVar(&maxConcurrency, "max-concurrency", 10, "最大并发扫描数")
	rootCmd.Flags().Int64Var(&maxFileSize, "max-file-size", 104857600, "最大文件大小 (字节)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "详细输出模式")
	rootCmd.Flags().BoolVar(&noProgress, "no-progress", false, "禁用进度条")

	// 执行命令
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	// 打印 banner
	printBanner()

	// 加载配置
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("加载配置失败: %w", err)
	}

	// 命令行参数覆盖配置
	if len(args) > 0 {
		cfg.Scan.Paths = args
	} else if len(scanPaths) > 0 {
		cfg.Scan.Paths = scanPaths
	}

	if outputDir != "" {
		cfg.Report.OutputDir = outputDir
	}

	if len(reportFormats) > 0 {
		cfg.Report.Formats = reportFormats
	}

	if maxConcurrency > 0 {
		cfg.Performance.MaxConcurrency = maxConcurrency
	}

	if maxFileSize > 0 {
		cfg.Scan.MaxFileSize = maxFileSize
	}

	if verbose {
		cfg.Report.Verbose = true
	}

	if noProgress {
		cfg.Performance.ShowProgress = false
	}

	// 验证配置
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("配置验证失败: %w", err)
	}

	// 打印配置信息
	printConfig(cfg)

	// 创建运行器
	r, err := runner.NewRunner(cfg)
	if err != nil {
		return fmt.Errorf("创建运行器失败: %w", err)
	}

	// 创建上下文，支持优雅退出
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 处理中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n\n收到中断信号，正在停止扫描...")
		cancel()
	}()

	// 运行扫描
	if err := r.Run(ctx); err != nil {
		return fmt.Errorf("扫描失败: %w", err)
	}

	return nil
}

func loadConfig() (*config.Config, error) {
	if configFile != "" {
		return config.LoadConfig(configFile)
	}
	// 尝试加载默认配置文件，如果不存在则使用默认配置
	cfg, err := config.LoadConfig("")
	if err != nil {
		// 使用默认配置
		return config.DefaultConfig(), nil
	}
	return cfg, nil
}

func printBanner() {
	banner := `
   ______ __    _             __  __   ____
  /_  __// /_  (_)__ ____ __/ / / /  / __/___  _____  _____
   / /  / __ \/ / _  / _  / _  / /  _\ \/ _  \/ __/ / / / /
  / /  / / / / / /_/ / /_/ / /_/ /  ___/ /  __/ /_ / /_/ /
 /_/  /_/ /_/_/\__, /\__,_/\____/  /____/\___/\__/ \____/
              /____/  知御安全敏感信息泄漏检测工具 v` + version + `
`
	fmt.Println(banner)
}

func printConfig(cfg *config.Config) {
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("📋 扫描配置")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("📁 扫描路径: %v\n", cfg.Scan.Paths)
	fmt.Printf("📊 最大文件大小: %d MB\n", cfg.Scan.MaxFileSize/1024/1024)
	fmt.Printf("🔀 最大并发数: %d\n", cfg.Performance.MaxConcurrency)
	fmt.Printf("📄 报告格式: %v\n", cfg.Report.Formats)
	fmt.Printf("📂 输出目录: %s\n", cfg.Report.OutputDir)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
}
