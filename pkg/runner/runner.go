// Package runner 提供扫描任务运行引擎
package runner

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/schollz/progressbar/v3"
	"github.com/zhiyusec/zhiyusec-leaks/pkg/config"
	"github.com/zhiyusec/zhiyusec-leaks/pkg/detect"
	"github.com/zhiyusec/zhiyusec-leaks/pkg/finding"
	"github.com/zhiyusec/zhiyusec-leaks/pkg/report"
	"github.com/zhiyusec/zhiyusec-leaks/pkg/sources"
)

// Runner 扫描运行器
type Runner struct {
	config   *config.Config
	scanner  *sources.Scanner
	detector *detect.Detector
	reporter *report.Reporter
	result   *finding.ScanResult
	logger   *slog.Logger
}

// NewRunner 创建新的运行器
func NewRunner(cfg *config.Config) (*Runner, error) {
	// 创建扫描器
	scanner, err := sources.NewScanner(cfg)
	if err != nil {
		return nil, fmt.Errorf("创建扫描器失败: %w", err)
	}

	// 创建检测器
	detector, err := detect.NewDetector(cfg)
	if err != nil {
		return nil, fmt.Errorf("创建检测器失败: %w", err)
	}

	// 创建报告器
	reporter := report.NewReporter(cfg)

	// 创建日志记录器
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	return &Runner{
		config:   cfg,
		scanner:  scanner,
		detector: detector,
		reporter: reporter,
		logger:   logger,
	}, nil
}

// Run 运行扫描任务
func (r *Runner) Run(ctx context.Context) error {
	r.logger.Info("开始扫描", "paths", r.config.Scan.Paths)

	// 创建扫描结果
	r.result = finding.NewScanResult(r.config.Scan.Paths)

	// 创建超时上下文
	timeoutCtx, cancel := context.WithTimeout(ctx, r.config.Performance.ScanTimeout)
	defer cancel()

	// 扫描文件系统
	fileChan, errChan := r.scanner.Scan(timeoutCtx, r.config.Scan.Paths)

	// 创建工作池
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, r.config.Performance.MaxConcurrency)

	// 收集所有文件
	var files []*sources.FileInfo
	for file := range fileChan {
		files = append(files, file)
	}

	// 检查扫描错误
	for err := range errChan {
		r.logger.Warn("扫描错误", "error", err)
	}

	r.logger.Info("文件收集完成", "total", len(files))

	// 创建进度条
	var bar *progressbar.ProgressBar
	if r.config.Performance.ShowProgress {
		bar = progressbar.NewOptions(len(files),
			progressbar.OptionSetDescription("扫描进度"),
			progressbar.OptionSetWidth(50),
			progressbar.OptionShowCount(),
			progressbar.OptionShowIts(),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "=",
				SaucerHead:    ">",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
		)
	}

	// 并发处理文件
	var mu sync.Mutex
	for _, file := range files {
		// 检查上下文是否已取消
		select {
		case <-timeoutCtx.Done():
			r.logger.Warn("扫描被取消或超时")
			wg.Wait()
			return r.finalize()
		default:
		}

		// 获取信号量
		semaphore <- struct{}{}
		wg.Add(1)

		go func(f *sources.FileInfo) {
			defer wg.Done()
			defer func() { <-semaphore }()

			// 更新进度条
			if bar != nil {
				defer bar.Add(1)
			}

			// 检查文件大小
			if f.Size > r.config.Scan.MaxFileSize {
				mu.Lock()
				r.result.AddLargeFile(f.Path, f.Size, "文件超过大小限制")
				mu.Unlock()
				return
			}

			// 检测文件
			findings, err := r.detector.DetectFile(timeoutCtx, f.Path)
			if err != nil {
				mu.Lock()
				r.result.AddError(f.Path, err.Error())
				mu.Unlock()
				r.logger.Warn("检测文件失败", "file", f.Path, "error", err)
				return
			}

			// 添加发现到结果
			if len(findings) > 0 {
				mu.Lock()
				for _, finding := range findings {
					r.result.AddFinding(finding)
				}
				mu.Unlock()

				r.logger.Info("发现敏感信息", "file", f.Path, "count", len(findings))
			}

			// 更新统计信息
			mu.Lock()
			r.result.TotalFiles++
			r.result.TotalBytes += f.Size
			mu.Unlock()
		}(file)
	}

	// 等待所有任务完成
	wg.Wait()

	return r.finalize()
}

// finalize 完成扫描并生成报告
func (r *Runner) finalize() error {
	// 完成扫描结果统计
	r.result.Finalize()

	// 获取扫描器统计信息
	stats := r.scanner.GetStats()

	r.logger.Info("扫描完成",
		"duration", r.result.Duration,
		"total_files", r.result.TotalFiles,
		"findings", len(r.result.Findings),
		"large_files", len(r.result.LargeFiles),
		"errors", len(r.result.Errors),
		"skipped_files", stats.SkippedFiles,
	)

	// 打印统计信息
	r.printSummary()

	// 生成报告
	r.logger.Info("生成报告", "formats", r.config.Report.Formats)
	if err := r.reporter.Generate(r.result); err != nil {
		return fmt.Errorf("生成报告失败: %w", err)
	}

	return nil
}

// printSummary 打印扫描摘要
func (r *Runner) printSummary() {
	fmt.Println("\n" + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("🛡️  知御安全 - 扫描完成")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("⏱️  扫描耗时: %s\n", r.result.Duration)
	fmt.Printf("📁 扫描文件: %d\n", r.result.TotalFiles)
	fmt.Printf("📊 文件大小: %d MB\n", r.result.TotalBytes/1024/1024)
	fmt.Printf("🔍 发现总数: %d\n", len(r.result.Findings))
	fmt.Println()

	// 按严重性统计
	if len(r.result.Findings) > 0 {
		fmt.Println("严重性分布:")
		for severity, count := range r.result.Statistics.BySeverity {
			if count > 0 {
				emoji := r.getSeverityEmoji(severity)
				fmt.Printf("  %s %s: %d\n", emoji, severity, count)
			}
		}
		fmt.Println()
	}

	// 超大文件
	if len(r.result.LargeFiles) > 0 {
		fmt.Printf("⚠️  超大文件: %d (未扫描)\n", len(r.result.LargeFiles))
	}

	// 错误
	if len(r.result.Errors) > 0 {
		fmt.Printf("❌ 错误: %d\n", len(r.result.Errors))
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

// getSeverityEmoji 获取严重性对应的 emoji
func (r *Runner) getSeverityEmoji(severity finding.Severity) string {
	switch severity {
	case finding.SeverityCritical:
		return "🔴"
	case finding.SeverityHigh:
		return "🟠"
	case finding.SeverityMedium:
		return "🟡"
	case finding.SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}

// GetResult 获取扫描结果
func (r *Runner) GetResult() *finding.ScanResult {
	return r.result
}
