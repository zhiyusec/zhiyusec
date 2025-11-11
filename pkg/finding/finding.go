// Package finding 定义扫描发现的数据结构
package finding

import (
	"time"
)

// Severity 严重性级别
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Finding 表示一个检测发现
type Finding struct {
	// 唯一标识符
	ID string `json:"id"`
	// 规则ID
	RuleID string `json:"rule_id"`
	// 规则描述
	Description string `json:"description"`
	// 文件路径
	FilePath string `json:"file_path"`
	// 行号
	LineNumber int `json:"line_number"`
	// 列号
	ColumnNumber int `json:"column_number"`
	// 匹配的内容
	Match string `json:"match"`
	// 匹配的秘密（部分遮蔽）
	Secret string `json:"secret"`
	// 上下文（匹配内容周围的代码）
	Context string `json:"context"`
	// 严重性级别
	Severity Severity `json:"severity"`
	// 置信度（0-100）
	Confidence int `json:"confidence"`
	// 熵值
	Entropy float64 `json:"entropy"`
	// 标签
	Tags []string `json:"tags"`
	// 发现时间
	Timestamp time.Time `json:"timestamp"`
	// 额外元数据
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ScanResult 扫描结果
type ScanResult struct {
	// 扫描开始时间
	StartTime time.Time `json:"start_time"`
	// 扫描结束时间
	EndTime time.Time `json:"end_time"`
	// 扫描持续时间
	Duration time.Duration `json:"duration"`
	// 扫描的根路径
	ScanPaths []string `json:"scan_paths"`
	// 扫描的文件总数
	TotalFiles int `json:"total_files"`
	// 扫描的文件大小总和
	TotalBytes int64 `json:"total_bytes"`
	// 检测到的发现列表
	Findings []*Finding `json:"findings"`
	// 超大文件列表
	LargeFiles []LargeFile `json:"large_files,omitempty"`
	// 错误列表
	Errors []ScanError `json:"errors,omitempty"`
	// 统计信息
	Statistics Statistics `json:"statistics"`
}

// LargeFile 超大文件信息
type LargeFile struct {
	// 文件路径
	Path string `json:"path"`
	// 文件大小
	Size int64 `json:"size"`
	// 原因
	Reason string `json:"reason"`
}

// ScanError 扫描错误
type ScanError struct {
	// 文件路径
	Path string `json:"path"`
	// 错误信息
	Error string `json:"error"`
	// 时间戳
	Timestamp time.Time `json:"timestamp"`
}

// Statistics 统计信息
type Statistics struct {
	// 按严重性分组的发现数量
	BySeverity map[Severity]int `json:"by_severity"`
	// 按规则分组的发现数量
	ByRule map[string]int `json:"by_rule"`
	// 按文件类型分组的发现数量
	ByFileType map[string]int `json:"by_file_type"`
	// 高熵值发现数量
	HighEntropyCount int `json:"high_entropy_count"`
}

// NewFinding 创建新的发现
func NewFinding(ruleID, description, filePath string, lineNum int) *Finding {
	return &Finding{
		ID:          generateID(),
		RuleID:      ruleID,
		Description: description,
		FilePath:    filePath,
		LineNumber:  lineNum,
		Severity:    SeverityMedium,
		Confidence:  50,
		Timestamp:   time.Now(),
		Tags:        []string{},
		Metadata:    make(map[string]interface{}),
	}
}

// NewScanResult 创建新的扫描结果
func NewScanResult(scanPaths []string) *ScanResult {
	return &ScanResult{
		StartTime:  time.Now(),
		ScanPaths:  scanPaths,
		Findings:   make([]*Finding, 0),
		LargeFiles: make([]LargeFile, 0),
		Errors:     make([]ScanError, 0),
		Statistics: Statistics{
			BySeverity: make(map[Severity]int),
			ByRule:     make(map[string]int),
			ByFileType: make(map[string]int),
		},
	}
}

// AddFinding 添加发现到结果
func (sr *ScanResult) AddFinding(f *Finding) {
	sr.Findings = append(sr.Findings, f)
	sr.Statistics.BySeverity[f.Severity]++
	sr.Statistics.ByRule[f.RuleID]++
}

// AddLargeFile 添加超大文件
func (sr *ScanResult) AddLargeFile(path string, size int64, reason string) {
	sr.LargeFiles = append(sr.LargeFiles, LargeFile{
		Path:   path,
		Size:   size,
		Reason: reason,
	})
}

// AddError 添加错误
func (sr *ScanResult) AddError(path, errMsg string) {
	sr.Errors = append(sr.Errors, ScanError{
		Path:      path,
		Error:     errMsg,
		Timestamp: time.Now(),
	})
}

// Finalize 完成扫描，计算统计信息
func (sr *ScanResult) Finalize() {
	sr.EndTime = time.Now()
	sr.Duration = sr.EndTime.Sub(sr.StartTime)
}

// GetFindingsBySeverity 按严重性过滤发现
func (sr *ScanResult) GetFindingsBySeverity(minSeverity Severity) []*Finding {
	severityOrder := map[Severity]int{
		SeverityLow:      1,
		SeverityMedium:   2,
		SeverityHigh:     3,
		SeverityCritical: 4,
	}

	minLevel := severityOrder[minSeverity]
	filtered := make([]*Finding, 0)

	for _, f := range sr.Findings {
		if severityOrder[f.Severity] >= minLevel {
			filtered = append(filtered, f)
		}
	}

	return filtered
}

// MaskSecret 遮蔽敏感信息
func MaskSecret(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}
	return secret[:4] + "****" + secret[len(secret)-4:]
}

// generateID 生成唯一ID
func generateID() string {
	return time.Now().Format("20060102150405.000000")
}
