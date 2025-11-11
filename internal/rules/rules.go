// Package rules 提供敏感信息检测规则管理
package rules

import (
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Rule 检测规则
type Rule struct {
	// 规则ID
	ID string `yaml:"id" json:"id"`
	// 规则描述
	Description string `yaml:"description" json:"description"`
	// 规则类型
	Type string `yaml:"type" json:"type"`
	// 正则表达式模式
	Pattern string `yaml:"pattern" json:"pattern"`
	// 编译后的正则表达式
	Regex *regexp.Regexp `yaml:"-" json:"-"`
	// 严重性级别
	Severity string `yaml:"severity" json:"severity"`
	// 标签
	Tags []string `yaml:"tags" json:"tags"`
	// 是否启用
	Enabled bool `yaml:"enabled" json:"enabled"`
	// 熵值检查阈值（可选）
	EntropyThreshold float64 `yaml:"entropy_threshold,omitempty" json:"entropy_threshold,omitempty"`
	// 关键词列表（用于多模式匹配）
	Keywords []string `yaml:"keywords,omitempty" json:"keywords,omitempty"`
	// 排除模式（排除误报）
	Exclusions []string `yaml:"exclusions,omitempty" json:"exclusions,omitempty"`
	// 额外元数据
	Metadata map[string]interface{} `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// RuleSet 规则集
type RuleSet struct {
	// 规则集版本
	Version string `yaml:"version" json:"version"`
	// 规则列表
	Rules []*Rule `yaml:"rules" json:"rules"`
}

// LoadRulesFromYAML 从 YAML 字符串加载规则
func LoadRulesFromYAML(data []byte) (*RuleSet, error) {
	var ruleSet RuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err != nil {
		return nil, fmt.Errorf("解析规则文件失败: %w", err)
	}

	// 编译所有规则的正则表达式
	for _, rule := range ruleSet.Rules {
		if rule.Pattern != "" {
			regex, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return nil, fmt.Errorf("编译规则 %s 的正则表达式失败: %w", rule.ID, err)
			}
			rule.Regex = regex
		}
	}

	return &ruleSet, nil
}

// GetEnabledRules 获取所有启用的规则
func (rs *RuleSet) GetEnabledRules() []*Rule {
	enabled := make([]*Rule, 0)
	for _, rule := range rs.Rules {
		if rule.Enabled {
			enabled = append(enabled, rule)
		}
	}
	return enabled
}

// GetRuleByID 根据ID获取规则
func (rs *RuleSet) GetRuleByID(id string) *Rule {
	for _, rule := range rs.Rules {
		if rule.ID == id {
			return rule
		}
	}
	return nil
}

// GetRulesByType 根据类型获取规则
func (rs *RuleSet) GetRulesByType(ruleType string) []*Rule {
	filtered := make([]*Rule, 0)
	for _, rule := range rs.Rules {
		if rule.Type == ruleType && rule.Enabled {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

// BuiltinRules 返回内置规则集
func BuiltinRules() *RuleSet {
	return &RuleSet{
		Version: "1.0.0",
		Rules: []*Rule{
			// API 密钥
			{
				ID:          "api-key-generic",
				Description: "检测通用 API 密钥",
				Type:        "api_key",
				Pattern:     `(?i)(api[_-]?key|apikey|api[_-]?secret)['":\s]*[=:]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?`,
				Severity:    "high",
				Tags:        []string{"api", "key", "secret"},
				Enabled:     true,
			},
			// AWS 访问密钥
			{
				ID:          "aws-access-key",
				Description: "检测 AWS 访问密钥",
				Type:        "api_key",
				Pattern:     `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
				Severity:    "critical",
				Tags:        []string{"aws", "access-key", "cloud"},
				Enabled:     true,
			},
			// AWS 秘密访问密钥
			{
				ID:          "aws-secret-key",
				Description: "检测 AWS 秘密访问密钥",
				Type:        "api_key",
				Pattern:     `(?i)aws[_-]?secret[_-]?access[_-]?key['":\s]*[=:]\s*['"]?([a-zA-Z0-9/+=]{40})['"]?`,
				Severity:    "critical",
				Tags:        []string{"aws", "secret-key", "cloud"},
				Enabled:     true,
			},
			// GitHub Token
			{
				ID:          "github-token",
				Description: "检测 GitHub 访问令牌",
				Type:        "token",
				Pattern:     `ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36}`,
				Severity:    "critical",
				Tags:        []string{"github", "token", "vcs"},
				Enabled:     true,
			},
			// 私钥
			{
				ID:          "private-key",
				Description: "检测 RSA/SSH 私钥",
				Type:        "private_key",
				Pattern:     `-----BEGIN\s+(RSA|OPENSSH|DSA|EC|PGP)\s+PRIVATE\s+KEY-----`,
				Severity:    "critical",
				Tags:        []string{"private-key", "ssh", "rsa"},
				Enabled:     true,
			},
			// 密码
			{
				ID:               "password-in-code",
				Description:      "检测代码中的密码",
				Type:             "password",
				Pattern:          `(?i)(password|passwd|pwd)['":\s]*[=:]\s*['"]([^'"]{6,})['"]`,
				Severity:         "medium",
				Tags:             []string{"password", "credential"},
				Enabled:          true,
				EntropyThreshold: 3.0,
			},
			// JWT Token
			{
				ID:          "jwt-token",
				Description: "检测 JWT 令牌",
				Type:        "token",
				Pattern:     `eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`,
				Severity:    "high",
				Tags:        []string{"jwt", "token", "auth"},
				Enabled:     true,
			},
			// 数据库连接字符串
			{
				ID:          "database-url",
				Description: "检测数据库连接字符串",
				Type:        "database_url",
				Pattern:     `(?i)(mongodb|mysql|postgresql|postgres|sqlite|redis|mssql|oracle):\/\/[^\s'"]+`,
				Severity:    "high",
				Tags:        []string{"database", "connection-string"},
				Enabled:     true,
			},
			// 邮箱地址
			{
				ID:          "email-address",
				Description: "检测邮箱地址",
				Type:        "email",
				Pattern:     `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
				Severity:    "low",
				Tags:        []string{"email", "pii"},
				Enabled:     true,
			},
			// 手机号码
			{
				ID:          "phone-number-cn",
				Description: "检测中国手机号码",
				Type:        "phone",
				Pattern:     `1[3-9]\d{9}`,
				Severity:    "low",
				Tags:        []string{"phone", "pii", "china"},
				Enabled:     true,
			},
			// 身份证号
			{
				ID:          "id-card-cn",
				Description: "检测中国身份证号",
				Type:        "id_card",
				Pattern:     `[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]`,
				Severity:    "high",
				Tags:        []string{"id-card", "pii", "china"},
				Enabled:     true,
			},
			// IP 地址
			{
				ID:          "ip-address",
				Description: "检测 IP 地址",
				Type:        "ip_address",
				Pattern:     `\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,
				Severity:    "low",
				Tags:        []string{"ip", "network"},
				Enabled:     true,
			},
			// Slack Token
			{
				ID:          "slack-token",
				Description: "检测 Slack Token",
				Type:        "token",
				Pattern:     `xox[baprs]-[0-9a-zA-Z]{10,48}`,
				Severity:    "high",
				Tags:        []string{"slack", "token"},
				Enabled:     true,
			},
			// Google API Key
			{
				ID:          "google-api-key",
				Description: "检测 Google API Key",
				Type:        "api_key",
				Pattern:     `AIza[0-9A-Za-z\\-_]{35}`,
				Severity:    "high",
				Tags:        []string{"google", "api-key"},
				Enabled:     true,
			},
		},
	}
}
