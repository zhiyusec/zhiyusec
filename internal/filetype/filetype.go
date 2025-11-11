// Package filetype 提供文件类型检测功能
package filetype

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FileType 文件类型
type FileType int

const (
	// TypeUnknown 未知类型
	TypeUnknown FileType = iota
	// TypeText 文本文件
	TypeText
	// TypeBinary 二进制文件
	TypeBinary
	// TypeArchive 归档文件
	TypeArchive
	// TypeImage 图片文件
	TypeImage
	// TypeVideo 视频文件
	TypeVideo
	// TypeAudio 音频文件
	TypeAudio
	// TypeExecutable 可执行文件
	TypeExecutable
)

// 文件扩展名映射
var (
	textExtensions = map[string]bool{
		".txt": true, ".md": true, ".json": true, ".yaml": true, ".yml": true,
		".xml": true, ".csv": true, ".log": true, ".conf": true, ".config": true,
		".ini": true, ".toml": true, ".properties": true,
		// 编程语言
		".go": true, ".py": true, ".java": true, ".c": true, ".cpp": true,
		".h": true, ".hpp": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".php": true, ".rb": true, ".rs": true, ".swift": true, ".kt": true,
		".scala": true, ".pl": true, ".sh": true, ".bash": true, ".zsh": true,
		".ps1": true, ".bat": true, ".cmd": true,
		// Web 相关
		".html": true, ".htm": true, ".css": true, ".scss": true, ".sass": true,
		".less": true, ".vue": true, ".svelte": true,
		// 数据格式
		".sql": true, ".graphql": true, ".proto": true,
		// 配置和脚本
		".dockerfile": true, ".gitignore": true, ".env": true,
		".editorconfig": true, ".prettierrc": true, ".eslintrc": true,
	}

	archiveExtensions = map[string]bool{
		".zip": true, ".tar": true, ".gz": true, ".bz2": true, ".xz": true,
		".7z": true, ".rar": true, ".tgz": true, ".tar.gz": true, ".tar.bz2": true,
		".tar.xz": true, ".jar": true, ".war": true, ".ear": true,
	}

	imageExtensions = map[string]bool{
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true,
		".svg": true, ".webp": true, ".ico": true, ".tif": true, ".tiff": true,
		".raw": true, ".heic": true, ".heif": true,
	}

	videoExtensions = map[string]bool{
		".mp4": true, ".avi": true, ".mov": true, ".mkv": true, ".flv": true,
		".wmv": true, ".webm": true, ".m4v": true, ".mpg": true, ".mpeg": true,
		".3gp": true, ".f4v": true,
	}

	audioExtensions = map[string]bool{
		".mp3": true, ".wav": true, ".flac": true, ".aac": true, ".ogg": true,
		".wma": true, ".m4a": true, ".ape": true, ".opus": true,
	}

	executableExtensions = map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true, ".app": true,
		".bin": true, ".out": true, ".elf": true, ".o": true, ".a": true,
	}

	// 二进制文件魔数（前几个字节）
	binarySignatures = map[string][]byte{
		"ELF":       {0x7F, 0x45, 0x4C, 0x46},                   // Linux 可执行文件
		"PE":        {0x4D, 0x5A},                               // Windows 可执行文件
		"Mach-O32":  {0xFE, 0xED, 0xFA, 0xCE},                   // macOS 32位可执行文件
		"Mach-O64":  {0xFE, 0xED, 0xFA, 0xCF},                   // macOS 64位可执行文件
		"ZIP":       {0x50, 0x4B, 0x03, 0x04},                   // ZIP 文件
		"GZIP":      {0x1F, 0x8B},                               // GZIP 文件
		"BZ2":       {0x42, 0x5A, 0x68},                         // BZ2 文件
		"7Z":        {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C},       // 7Z 文件
		"PNG":       {0x89, 0x50, 0x4E, 0x47},                   // PNG 图片
		"JPEG":      {0xFF, 0xD8, 0xFF},                         // JPEG 图片
		"PDF":       {0x25, 0x50, 0x44, 0x46},                   // PDF 文件
		"CLASS":     {0xCA, 0xFE, 0xBA, 0xBE},                   // Java Class 文件
	}
)

// DetectFileType 检测文件类型
func DetectFileType(filePath string) FileType {
	// 首先基于扩展名判断
	ext := strings.ToLower(filepath.Ext(filePath))

	if textExtensions[ext] {
		return TypeText
	}
	if archiveExtensions[ext] {
		return TypeArchive
	}
	if imageExtensions[ext] {
		return TypeImage
	}
	if videoExtensions[ext] {
		return TypeVideo
	}
	if audioExtensions[ext] {
		return TypeAudio
	}
	if executableExtensions[ext] {
		return TypeExecutable
	}

	// 如果扩展名无法判断，读取文件头判断
	fileType := detectByMagicNumber(filePath)
	if fileType != TypeUnknown {
		return fileType
	}

	// 尝试判断是否为文本文件
	if isTextFile(filePath) {
		return TypeText
	}

	return TypeBinary
}

// detectByMagicNumber 通过魔数检测文件类型
func detectByMagicNumber(filePath string) FileType {
	file, err := os.Open(filePath)
	if err != nil {
		return TypeUnknown
	}
	defer file.Close()

	// 读取前 512 字节用于判断
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return TypeUnknown
	}
	buffer = buffer[:n]

	// 检查各种文件签名
	for sigType, signature := range binarySignatures {
		if len(buffer) >= len(signature) && bytesEqual(buffer[:len(signature)], signature) {
			switch {
			case sigType == "ELF" || sigType == "PE" || strings.HasPrefix(sigType, "Mach-O") || sigType == "CLASS":
				return TypeExecutable
			case sigType == "ZIP" || sigType == "GZIP" || sigType == "BZ2" || sigType == "7Z":
				return TypeArchive
			case sigType == "PNG" || sigType == "JPEG":
				return TypeImage
			case sigType == "PDF":
				return TypeBinary
			}
		}
	}

	return TypeUnknown
}

// isTextFile 判断是否为文本文件（通过检查是否包含不可打印字符）
func isTextFile(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	// 读取前 8192 字节进行检测
	buffer := make([]byte, 8192)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return false
	}
	buffer = buffer[:n]

	// 检查是否包含过多的不可打印字符
	nonPrintableCount := 0
	for _, b := range buffer {
		// ASCII 可打印字符范围：32-126，加上常见空白字符：9(tab), 10(LF), 13(CR)
		if !(b >= 32 && b <= 126) && b != 9 && b != 10 && b != 13 {
			nonPrintableCount++
		}
	}

	// 如果不可打印字符超过 30%，认为是二进制文件
	threshold := float64(len(buffer)) * 0.3
	return float64(nonPrintableCount) < threshold
}

// ShouldScan 判断是否应该扫描该文件
func ShouldScan(filePath string) bool {
	fileType := DetectFileType(filePath)
	// 只扫描文本文件和归档文件
	return fileType == TypeText || fileType == TypeArchive
}

// IsArchive 判断是否为归档文件
func IsArchive(filePath string) bool {
	return DetectFileType(filePath) == TypeArchive
}

// IsTextFile 判断是否为文本文件
func IsTextFile(filePath string) bool {
	return DetectFileType(filePath) == TypeText
}

// bytesEqual 比较两个字节切片是否相等
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// GetFileTypeString 获取文件类型的字符串表示
func GetFileTypeString(ft FileType) string {
	switch ft {
	case TypeText:
		return "text"
	case TypeBinary:
		return "binary"
	case TypeArchive:
		return "archive"
	case TypeImage:
		return "image"
	case TypeVideo:
		return "video"
	case TypeAudio:
		return "audio"
	case TypeExecutable:
		return "executable"
	default:
		return "unknown"
	}
}
