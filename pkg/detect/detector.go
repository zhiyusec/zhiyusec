// Package detect 提供敏感信息检测功能
package detect

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/zhiyusec/zhiyusec-leaks/internal/rules"
	"github.com/zhiyusec/zhiyusec-leaks/pkg/config"
	"github.com/zhiyusec/zhiyusec-leaks/pkg/finding"
	"github.com/zhiyusec/zhiyusec-leaks/pkg/utils"
)

// Detector 检测器
type Detector struct {
	config  *config.Config
	ruleSet *rules.RuleSet
}

// NewDetector 创建新的检测器
func NewDetector(cfg *config.Config) (*Detector, error) {
	detector := &Detector{
		config: cfg,
	}

	// 加载内置规则
	if cfg.Detect.EnableBuiltinRules {
		detector.ruleSet = rules.BuiltinRules()
	} else {
		detector.ruleSet = &rules.RuleSet{
			Version: "1.0.0",
			Rules:   make([]*rules.Rule, 0),
		}
	}

	// 加载自定义规则文件
	for _, ruleFile := range cfg.Detect.RuleFiles {
		if err := detector.loadRuleFile(ruleFile); err != nil {
			// 如果规则文件不存在，仅记录警告，不返回错误
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("加载规则文件 %s 失败: %w", ruleFile, err)
			}
		}
	}

	return detector, nil
}

// loadRuleFile 加载规则文件
func (d *Detector) loadRuleFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	ruleSet, err := rules.LoadRulesFromYAML(data)
	if err != nil {
		return err
	}

	// 合并规则
	d.ruleSet.Rules = append(d.ruleSet.Rules, ruleSet.Rules...)

	return nil
}

// DetectFile 检测单个文件
func (d *Detector) DetectFile(ctx context.Context, filePath string) ([]*finding.Finding, error) {
	// 检查上下文是否已取消
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	findings := make([]*finding.Finding, 0)

	// 逐行读取文件
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, d.config.Performance.BufferSize), d.config.Performance.BufferSize*2)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// 检查行是否匹配任何规则
		lineFindings := d.detectLine(filePath, line, lineNum)
		findings = append(findings, lineFindings...)

		// 检查上下文
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
	}

	if err := scanner.Err(); err != nil {
		return findings, fmt.Errorf("读取文件失败: %w", err)
	}

	return findings, nil
}

// detectLine 检测单行文本
func (d *Detector) detectLine(filePath, line string, lineNum int) []*finding.Finding {
	findings := make([]*finding.Finding, 0)

	// 对每个启用的规则进行检测
	for _, rule := range d.ruleSet.GetEnabledRules() {
		// 检查规则类型是否启用
		if !d.isRuleTypeEnabled(rule.Type) {
			continue
		}

		// 使用正则表达式匹配
		if rule.Regex != nil {
			matches := rule.Regex.FindAllStringSubmatchIndex(line, -1)
			for _, match := range matches {
				if len(match) >= 2 {
					start, end := match[0], match[1]
					matchedText := line[start:end]

					// 检查排除模式
					if d.shouldExclude(matchedText, rule.Exclusions) {
						continue
					}

					// 创建发现
					f := finding.NewFinding(rule.ID, rule.Description, filePath, lineNum)
					f.Match = matchedText
					f.Secret = finding.MaskSecret(matchedText)
					f.ColumnNumber = start + 1
					f.Context = d.getContext(line, start, end)
					f.Severity = finding.Severity(rule.Severity)
					f.Tags = rule.Tags

					// 计算熵值
					if d.config.Detect.EnableEntropyCheck {
						entropy := utils.CalculateEntropy(matchedText)
						f.Entropy = entropy

						// 如果规则设置了熵值阈值，检查是否满足
						if rule.EntropyThreshold > 0 && entropy < rule.EntropyThreshold {
							continue
						}

						// 如果熵值过低，降低置信度
						if entropy < d.config.Detect.EntropyThreshold {
							f.Confidence = 30
						} else {
							f.Confidence = 80
						}
					} else {
						f.Confidence = 70
					}

					findings = append(findings, f)
				}
			}
		}

		// 关键词匹配
		if len(rule.Keywords) > 0 {
			for _, keyword := range rule.Keywords {
				if strings.Contains(strings.ToLower(line), strings.ToLower(keyword)) {
					f := finding.NewFinding(rule.ID, rule.Description, filePath, lineNum)
					f.Match = keyword
					f.Secret = finding.MaskSecret(keyword)
					f.Context = line
					f.Severity = finding.Severity(rule.Severity)
					f.Tags = rule.Tags
					f.Confidence = 50

					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// getContext 获取匹配内容的上下文
func (d *Detector) getContext(line string, start, end int) string {
	const contextSize = 50

	contextStart := start - contextSize
	if contextStart < 0 {
		contextStart = 0
	}

	contextEnd := end + contextSize
	if contextEnd > len(line) {
		contextEnd = len(line)
	}

	return line[contextStart:contextEnd]
}

// shouldExclude 检查是否应该排除
func (d *Detector) shouldExclude(text string, exclusions []string) bool {
	for _, pattern := range exclusions {
		if utils.MatchesPattern(text, pattern) {
			return true
		}
	}
	return false
}

// isRuleTypeEnabled 检查规则类型是否启用
func (d *Detector) isRuleTypeEnabled(ruleType string) bool {
	if len(d.config.Detect.EnabledTypes) == 0 {
		return true
	}
	enabled, ok := d.config.Detect.EnabledTypes[ruleType]
	if !ok {
		return true
	}
	return enabled
}

// GetRuleSet 获取规则集
func (d *Detector) GetRuleSet() *rules.RuleSet {
	return d.ruleSet
}
