package normalize

// 路径穿越检测器
// 多层解码后检测 ../ 和 ..\ 遍历模式、绝对路径、协议包装器

import (
	"strings"
)

const PathTraversalAttackType = "路径穿越"

// PathTraversalResult 路径穿越检测结果
type PathTraversalResult struct {
	Detected bool
	Detail   string
}

// DetectPathTraversal 对规范化后的值检测路径穿越
// 输入应为 Pipeline.Normalize 输出的 Normalized 值
func DetectPathTraversal(normalized string) PathTraversalResult {
	lower := strings.ToLower(normalized)

	if p := detectDotDotSegments(lower); p.Detected {
		return p
	}
	if p := detectAbsolutePath(lower); p.Detected {
		return p
	}
	if p := detectProtocolWrapper(lower); p.Detected {
		return p
	}
	if p := detectNullByte(lower); p.Detected {
		return p
	}
	return PathTraversalResult{}
}

// detectDotDotSegments 检测 ../ ..\ 和变体
func detectDotDotSegments(s string) PathTraversalResult {
	cleaned := strings.ReplaceAll(s, "\\", "/")
	segments := strings.Split(cleaned, "/")
	depth := 0
	for _, seg := range segments {
		trimmed := strings.TrimSpace(seg)
		if trimmed == ".." {
			depth--
			if depth < 0 {
				return PathTraversalResult{Detected: true, Detail: "检测到路径向上穿越 (..)"}
			}
		} else if trimmed != "" && trimmed != "." {
			depth++
		}
	}
	if strings.Contains(cleaned, "../") || strings.Contains(cleaned, "..\\") {
		return PathTraversalResult{Detected: true, Detail: "检测到路径穿越序列 (../)"}
	}
	return PathTraversalResult{}
}

// detectAbsolutePath 检测绝对路径（Unix / Windows）
func detectAbsolutePath(s string) PathTraversalResult {
	if strings.HasPrefix(s, "/etc/") || strings.HasPrefix(s, "/proc/") ||
		strings.HasPrefix(s, "/var/") || strings.HasPrefix(s, "/root/") ||
		strings.HasPrefix(s, "/home/") || strings.HasPrefix(s, "/tmp/") {
		return PathTraversalResult{Detected: true, Detail: "检测到 Unix 绝对路径访问"}
	}
	if len(s) >= 3 && s[0] >= 'a' && s[0] <= 'z' && s[1] == ':' && (s[2] == '/' || s[2] == '\\') {
		return PathTraversalResult{Detected: true, Detail: "检测到 Windows 绝对路径访问"}
	}
	if strings.HasPrefix(s, "\\\\") {
		return PathTraversalResult{Detected: true, Detail: "检测到 UNC 路径访问"}
	}
	return PathTraversalResult{}
}

// detectProtocolWrapper 检测 file:// php:// phar:// jar:// 等协议包装器
func detectProtocolWrapper(s string) PathTraversalResult {
	dangerousSchemes := []string{
		"file://", "php://", "phar://", "jar://", "zip://",
		"glob://", "data://", "expect://", "input://",
		"dict://", "ftp://", "gopher://",
	}
	for _, scheme := range dangerousSchemes {
		if strings.HasPrefix(s, scheme) {
			return PathTraversalResult{Detected: true, Detail: "检测到协议包装器: " + scheme}
		}
	}
	return PathTraversalResult{}
}

// detectNullByte 检测空字节注入（截断攻击）
func detectNullByte(s string) PathTraversalResult {
	if strings.ContainsRune(s, 0) {
		return PathTraversalResult{Detected: true, Detail: "检测到空字节注入"}
	}
	return PathTraversalResult{}
}
