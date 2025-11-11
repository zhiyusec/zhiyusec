// Package report 提供报告生成功能
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/zhiyusec/zhiyusec-leaks/pkg/config"
	"github.com/zhiyusec/zhiyusec-leaks/pkg/finding"
)

// Reporter 报告生成器
type Reporter struct {
	config *config.Config
}

// NewReporter 创建新的报告生成器
func NewReporter(cfg *config.Config) *Reporter {
	return &Reporter{
		config: cfg,
	}
}

// Generate 生成报告
func (r *Reporter) Generate(result *finding.ScanResult) error {
	// 确保输出目录存在
	if err := os.MkdirAll(r.config.Report.OutputDir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	// 根据配置的格式生成报告
	for _, format := range r.config.Report.Formats {
		switch format {
		case "json":
			if err := r.generateJSON(result); err != nil {
				return fmt.Errorf("生成 JSON 报告失败: %w", err)
			}
		case "csv":
			if err := r.generateCSV(result); err != nil {
				return fmt.Errorf("生成 CSV 报告失败: %w", err)
			}
		case "html":
			if err := r.generateHTML(result); err != nil {
				return fmt.Errorf("生成 HTML 报告失败: %w", err)
			}
		case "sarif":
			if err := r.generateSARIF(result); err != nil {
				return fmt.Errorf("生成 SARIF 报告失败: %w", err)
			}
		default:
			return fmt.Errorf("不支持的报告格式: %s", format)
		}
	}

	return nil
}

// generateJSON 生成 JSON 格式报告
func (r *Reporter) generateJSON(result *finding.ScanResult) error {
	fileName := r.getFileName("json")
	filePath := filepath.Join(r.config.Report.OutputDir, fileName)

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// 过滤结果
	filteredResult := r.filterResult(result)

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(filteredResult); err != nil {
		return err
	}

	fmt.Printf("JSON 报告已生成: %s\n", filePath)
	return nil
}

// generateCSV 生成 CSV 格式报告
func (r *Reporter) generateCSV(result *finding.ScanResult) error {
	fileName := r.getFileName("csv")
	filePath := filepath.Join(r.config.Report.OutputDir, fileName)

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	header := []string{"ID", "规则ID", "描述", "文件路径", "行号", "列号", "严重性", "置信度", "熵值", "匹配内容", "标签"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// 写入数据
	filteredFindings := r.filterFindings(result.Findings)
	for _, f := range filteredFindings {
		record := []string{
			f.ID,
			f.RuleID,
			f.Description,
			f.FilePath,
			fmt.Sprintf("%d", f.LineNumber),
			fmt.Sprintf("%d", f.ColumnNumber),
			string(f.Severity),
			fmt.Sprintf("%d", f.Confidence),
			fmt.Sprintf("%.2f", f.Entropy),
			f.Secret,
			fmt.Sprintf("%v", f.Tags),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	fmt.Printf("CSV 报告已生成: %s\n", filePath)
	return nil
}

// generateHTML 生成 HTML 格式报告
func (r *Reporter) generateHTML(result *finding.ScanResult) error {
	fileName := r.getFileName("html")
	filePath := filepath.Join(r.config.Report.OutputDir, fileName)

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	filteredResult := r.filterResult(result)

	// 创建辅助函数
	funcMap := template.FuncMap{
		"getSeverityCount": func(stats map[finding.Severity]int, severity string) int {
			return stats[finding.Severity(severity)]
		},
	}

	tmpl := template.Must(template.New("report").Funcs(funcMap).Parse(htmlTemplate))
	if err := tmpl.Execute(file, filteredResult); err != nil {
		return err
	}

	fmt.Printf("HTML 报告已生成: %s\n", filePath)
	return nil
}

// generateSARIF 生成 SARIF 格式报告
func (r *Reporter) generateSARIF(result *finding.ScanResult) error {
	fileName := r.getFileName("sarif")
	filePath := filepath.Join(r.config.Report.OutputDir, fileName)

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// 构建 SARIF 格式
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "zhiyusec-leaks",
						"version": "1.0.0",
						"informationUri": "https://github.com/zhiyusec/zhiyusec-leaks",
					},
				},
				"results": r.buildSARIFResults(result),
			},
		},
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(sarif); err != nil {
		return err
	}

	fmt.Printf("SARIF 报告已生成: %s\n", filePath)
	return nil
}

// buildSARIFResults 构建 SARIF 结果
func (r *Reporter) buildSARIFResults(result *finding.ScanResult) []map[string]interface{} {
	results := make([]map[string]interface{}, 0)

	filteredFindings := r.filterFindings(result.Findings)
	for _, f := range filteredFindings {
		sarifResult := map[string]interface{}{
			"ruleId": f.RuleID,
			"message": map[string]interface{}{
				"text": f.Description,
			},
			"level": r.severityToSARIFLevel(f.Severity),
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": f.FilePath,
						},
						"region": map[string]interface{}{
							"startLine":   f.LineNumber,
							"startColumn": f.ColumnNumber,
						},
					},
				},
			},
		}
		results = append(results, sarifResult)
	}

	return results
}

// severityToSARIFLevel 将严重性转换为 SARIF 级别
func (r *Reporter) severityToSARIFLevel(severity finding.Severity) string {
	switch severity {
	case finding.SeverityCritical:
		return "error"
	case finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	case finding.SeverityLow:
		return "note"
	default:
		return "note"
	}
}

// filterResult 过滤扫描结果
func (r *Reporter) filterResult(result *finding.ScanResult) *finding.ScanResult {
	filtered := *result
	filtered.Findings = r.filterFindings(result.Findings)

	if !r.config.Report.IncludeLargeFiles {
		filtered.LargeFiles = nil
	}

	return &filtered
}

// filterFindings 根据配置过滤发现
func (r *Reporter) filterFindings(findings []*finding.Finding) []*finding.Finding {
	// 根据最小严重性级别过滤
	severityOrder := map[finding.Severity]int{
		finding.SeverityLow:      1,
		finding.SeverityMedium:   2,
		finding.SeverityHigh:     3,
		finding.SeverityCritical: 4,
	}

	minLevel := severityOrder[finding.Severity(r.config.Report.MinSeverity)]
	filtered := make([]*finding.Finding, 0)

	for _, f := range findings {
		if severityOrder[f.Severity] >= minLevel {
			filtered = append(filtered, f)
		}
	}

	return filtered
}

// getFileName 生成报告文件名
func (r *Reporter) getFileName(extension string) string {
	timestamp := time.Now().Format("20060102-150405")
	return fmt.Sprintf("%s-%s.%s", r.config.Report.FilePrefix, timestamp, extension)
}

// HTML 模板
const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>知御安全 - 敏感信息扫描报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #007BFF; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat-box { background: white; padding: 15px; border-radius: 5px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-box h3 { margin: 0; color: #007BFF; }
        .stat-box p { margin: 5px 0 0 0; font-size: 24px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 5px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #007BFF; color: white; }
        tr:hover { background: #f1f1f1; }
        .critical { color: #dc3545; font-weight: bold; }
        .high { color: #fd7e14; font-weight: bold; }
        .medium { color: #ffc107; font-weight: bold; }
        .low { color: #28a745; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ 知御安全 - 敏感信息扫描报告</h1>
        <p>扫描时间: {{.StartTime.Format "2006-01-02 15:04:05"}}</p>
        <p>扫描耗时: {{.Duration}}</p>
    </div>

    <div class="stats">
        <div class="stat-box">
            <h3>扫描文件</h3>
            <p>{{.TotalFiles}}</p>
        </div>
        <div class="stat-box">
            <h3>发现总数</h3>
            <p>{{len .Findings}}</p>
        </div>
        <div class="stat-box">
            <h3>严重问题</h3>
            <p class="critical">{{getSeverityCount .Statistics.BySeverity "critical"}}</p>
        </div>
        <div class="stat-box">
            <h3>高危问题</h3>
            <p class="high">{{getSeverityCount .Statistics.BySeverity "high"}}</p>
        </div>
    </div>

    <div class="summary">
        <h2>扫描详情</h2>
        <table>
            <thead>
                <tr>
                    <th>文件路径</th>
                    <th>行号</th>
                    <th>规则</th>
                    <th>描述</th>
                    <th>严重性</th>
                    <th>置信度</th>
                </tr>
            </thead>
            <tbody>
                {{range .Findings}}
                <tr>
                    <td>{{.FilePath}}</td>
                    <td>{{.LineNumber}}</td>
                    <td>{{.RuleID}}</td>
                    <td>{{.Description}}</td>
                    <td class="{{.Severity}}">{{.Severity}}</td>
                    <td>{{.Confidence}}%</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>

    <div class="summary">
        <p><em>报告生成于: {{.EndTime.Format "2006-01-02 15:04:05"}}</em></p>
        <p><em>Powered by zhiyusec-leaks © 2025</em></p>
    </div>
</body>
</html>
`
