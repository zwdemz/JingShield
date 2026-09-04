package normalize

// XXE/XML 流式检测器
// 不解析完整 DOM，而是扫描 XML 文本中的危险标记：
// DTD 声明、外部实体、SYSTEM/PUBLIC 标识符、XInclude、CDATA 嵌套

import (
	"strings"
)

const XXEAttackType = "XXE"

// XXEResult XXE 检测结果
type XXEResult struct {
	Detected bool
	Detail   string
}

// DetectXXE 对 XML/文本内容执行 XXE 特征扫描
// 输入应为规范化后的值（已解码 HTML 实体和 URL 编码）
func DetectXXE(normalized string) XXEResult {
	lower := strings.ToLower(normalized)

	if r := detectDTDDeclaration(lower); r.Detected {
		return r
	}
	if r := detectExternalEntity(lower); r.Detected {
		return r
	}
	if r := detectXInclude(lower); r.Detected {
		return r
	}
	if r := detectParameterEntity(lower); r.Detected {
		return r
	}
	if r := detectDOCTYPEAbuse(lower); r.Detected {
		return r
	}

	return XXEResult{}
}

// detectDTDDeclaration 检测 <!DOCTYPE 声明
func detectDTDDeclaration(s string) XXEResult {
	if strings.Contains(s, "<!doctype") {
		if strings.Contains(s, "system") || strings.Contains(s, "public") ||
			strings.Contains(s, "<!entity") {
			return XXEResult{Detected: true, Detail: "检测到带外部引用的 DOCTYPE 声明"}
		}
	}
	return XXEResult{}
}

// detectExternalEntity 检测 <!ENTITY ... SYSTEM/PUBLIC
func detectExternalEntity(s string) XXEResult {
	if !strings.Contains(s, "<!entity") {
		return XXEResult{}
	}
	if strings.Contains(s, "system") {
		return XXEResult{Detected: true, Detail: "检测到 SYSTEM 外部实体声明"}
	}
	if strings.Contains(s, "public") {
		return XXEResult{Detected: true, Detail: "检测到 PUBLIC 外部实体声明"}
	}
	return XXEResult{}
}

// detectXInclude 检测 XInclude 注入
func detectXInclude(s string) XXEResult {
	xincludePatterns := []string{
		"xi:include",
		"xinclude:",
		"xmlns:xi=",
		"http://www.w3.org/2001/xinclude",
	}
	for _, pattern := range xincludePatterns {
		if strings.Contains(s, pattern) {
			return XXEResult{Detected: true, Detail: "检测到 XInclude 注入"}
		}
	}
	return XXEResult{}
}

// detectParameterEntity 检测参数实体（% 前缀）用于盲 XXE
func detectParameterEntity(s string) XXEResult {
	if !strings.Contains(s, "<!entity") {
		return XXEResult{}
	}
	cleaned := strings.ReplaceAll(s, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "\t", "")
	cleaned = strings.ReplaceAll(cleaned, "\n", "")
	if strings.Contains(cleaned, "%") && (strings.Contains(cleaned, "system") || strings.Contains(cleaned, "public")) {
		return XXEResult{Detected: true, Detail: "检测到参数实体（盲 XXE）"}
	}
	return XXEResult{}
}

// detectDOCTYPEAbuse 检测 DOCTYPE 内嵌大量实体（Billion Laughs / 实体扩展炸弹）
func detectDOCTYPEAbuse(s string) XXEResult {
	if !strings.Contains(s, "<!doctype") {
		return XXEResult{}
	}
	entityCount := strings.Count(s, "<!entity")
	if entityCount > 10 {
		return XXEResult{Detected: true, Detail: "检测到异常数量的实体声明（可能的实体扩展攻击）"}
	}
	referenceCount := 0
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '&' && s[i+1] != '#' && s[i+1] != ' ' {
			referenceCount++
		}
	}
	if entityCount > 0 && referenceCount > entityCount*5 {
		return XXEResult{Detected: true, Detail: "检测到实体引用异常比例（可能的 Billion Laughs 攻击）"}
	}
	return XXEResult{}
}
