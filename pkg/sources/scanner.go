// Package sources 提供文件系统遍历功能
package sources

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/zhiyusec/zhiyusec-leaks/internal/filetype"
	"github.com/zhiyusec/zhiyusec-leaks/pkg/config"
)

// FileInfo 文件信息
type FileInfo struct {
	// 文件路径
	Path string
	// 文件大小
	Size int64
	// 文件类型
	Type filetype.FileType
	// 是否为归档文件
	IsArchive bool
}

// Scanner 文件扫描器
type Scanner struct {
	config    *config.Config
	blacklist []*regexp.Regexp
	whitelist []*regexp.Regexp
	mu        sync.Mutex
	stats     ScanStats
}

// ScanStats 扫描统计信息
type ScanStats struct {
	TotalFiles   int
	TotalBytes   int64
	SkippedFiles int
	LargeFiles   int
}

// NewScanner 创建新的扫描器
func NewScanner(cfg *config.Config) (*Scanner, error) {
	scanner := &Scanner{
		config: cfg,
	}

	// 编译黑名单正则表达式
	for _, pattern := range cfg.Scan.Blacklist {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("编译黑名单正则表达式失败 %s: %w", pattern, err)
		}
		scanner.blacklist = append(scanner.blacklist, re)
	}

	// 编译白名单正则表达式
	for _, pattern := range cfg.Scan.Whitelist {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("编译白名单正则表达式失败 %s: %w", pattern, err)
		}
		scanner.whitelist = append(scanner.whitelist, re)
	}

	return scanner, nil
}

// Scan 扫描指定路径
func (s *Scanner) Scan(ctx context.Context, paths []string) (<-chan *FileInfo, <-chan error) {
	fileChan := make(chan *FileInfo, 100)
	errChan := make(chan error, 10)

	go func() {
		defer close(fileChan)
		defer close(errChan)

		for _, path := range paths {
			if err := s.scanPath(ctx, path, fileChan, errChan); err != nil {
				errChan <- err
			}
		}
	}()

	return fileChan, errChan
}

// scanPath 扫描单个路径
func (s *Scanner) scanPath(ctx context.Context, root string, fileChan chan<- *FileInfo, errChan chan<- error) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			errChan <- fmt.Errorf("访问路径 %s 失败: %w", path, err)
			return nil // 继续遍历其他文件
		}

		// 跳过目录
		if info.IsDir() {
			return nil
		}

		// 跳过符号链接（如果配置要求）
		if info.Mode()&os.ModeSymlink != 0 && !s.config.Scan.FollowSymlinks {
			s.incrementSkipped()
			return nil
		}

		// 检查黑白名单
		if !s.shouldScan(path) {
			s.incrementSkipped()
			return nil
		}

		// 检查文件大小
		size := info.Size()
		if size > s.config.Scan.MaxFileSize {
			s.incrementLargeFiles()
			// 仍然发送大文件信息，但标记为大文件
			fileChan <- &FileInfo{
				Path:      path,
				Size:      size,
				Type:      filetype.TypeUnknown,
				IsArchive: false,
			}
			return nil
		}

		// 检测文件类型
		fileType := filetype.DetectFileType(path)
		isArchive := filetype.IsArchive(path)

		// 跳过不需要扫描的文件类型
		if !filetype.ShouldScan(path) {
			s.incrementSkipped()
			return nil
		}

		// 发送文件信息到通道
		s.incrementStats(size)
		fileChan <- &FileInfo{
			Path:      path,
			Size:      size,
			Type:      fileType,
			IsArchive: isArchive,
		}

		return nil
	})
}

// shouldScan 检查文件是否应该被扫描（黑白名单过滤）
func (s *Scanner) shouldScan(path string) bool {
	// 如果有白名单，只扫描白名单中的文件
	if len(s.whitelist) > 0 {
		for _, re := range s.whitelist {
			if re.MatchString(path) {
				return true
			}
		}
		return false
	}

	// 检查黑名单
	for _, re := range s.blacklist {
		if re.MatchString(path) {
			return false
		}
	}

	return true
}

// incrementStats 增加统计信息
func (s *Scanner) incrementStats(size int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.TotalFiles++
	s.stats.TotalBytes += size
}

// incrementSkipped 增加跳过文件计数
func (s *Scanner) incrementSkipped() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.SkippedFiles++
}

// incrementLargeFiles 增加大文件计数
func (s *Scanner) incrementLargeFiles() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.LargeFiles++
}

// GetStats 获取扫描统计信息
func (s *Scanner) GetStats() ScanStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}
