// Package utils 提供通用工具函数
package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
)

// CalculateEntropy 计算字符串的熵值
// 熵值越高，表示字符串越随机
func CalculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0.0
	}

	// 统计每个字符出现的频率
	frequencies := make(map[rune]int)
	for _, char := range data {
		frequencies[char]++
	}

	// 计算熵值
	var entropy float64
	dataLen := float64(len(data))
	for _, count := range frequencies {
		frequency := float64(count) / dataLen
		entropy -= frequency * math.Log2(frequency)
	}

	return entropy
}

// CalculateSHA256 计算字符串的 SHA256 哈希值
func CalculateSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// IsBase64 判断字符串是否为 Base64 编码
func IsBase64(s string) bool {
	// Base64 正则表达式
	base64Regex := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	if !base64Regex.MatchString(s) {
		return false
	}
	// Base64 字符串长度必须是4的倍数
	return len(s)%4 == 0
}

// IsHex 判断字符串是否为十六进制编码
func IsHex(s string) bool {
	hexRegex := regexp.MustCompile(`^[0-9a-fA-F]+$`)
	return hexRegex.MatchString(s)
}

// TruncateString 截断字符串到指定长度
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// ContainsAny 检查字符串是否包含列表中的任意一个子串
func ContainsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if regexp.MustCompile(substr).MatchString(s) {
			return true
		}
	}
	return false
}

// MatchesPattern 检查字符串是否匹配指定的正则表达式
func MatchesPattern(s string, pattern string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

// SanitizePath 清理路径字符串，移除不安全的字符
func SanitizePath(path string) string {
	// 移除路径遍历字符
	unsafeChars := regexp.MustCompile(`\.\.`)
	return unsafeChars.ReplaceAllString(path, "")
}

// BytesToHumanReadable 将字节数转换为人类可读的格式
func BytesToHumanReadable(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return string(bytes) + " B"
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	return string(bytes/div) + " " + units[exp]
}
