package normalize

// 公共规范化管线
// 所有语义检测器的输入预处理底座
//
// 设计原则：
//   - 有界多层：URL/HTML/Unicode 解码设最大迭代次数，防止 ReDoS 和 CPU 耗尽
//   - 来源追踪：每个参数值保留原值、规范值和来源标记（query/form/cookie/body/header/path）
//   - 限制保护：解码深度、节点数和输出大小均可配置上限
//   - 幂等收敛：当连续两轮解码结果相同时停止迭代

import (
	"strings"
)

const (
	DefaultMaxDecodeRounds = 5
	DefaultMaxOutputBytes  = 8192
)

// Source 参数来源
type Source int

const (
	SourceQuery   Source = iota // URL query 参数
	SourceForm                  // POST form 参数
	SourceCookie                // Cookie 值
	SourceBody                  // JSON/XML/text body
	SourceHeader                // HTTP header 值
	SourcePath                  // URL path
)

func (s Source) String() string {
	switch s {
	case SourceQuery:
		return "query"
	case SourceForm:
		return "form"
	case SourceCookie:
		return "cookie"
	case SourceBody:
		return "body"
	case SourceHeader:
		return "header"
	case SourcePath:
		return "path"
	default:
		return "unknown"
	}
}

// Value 规范化结果
type Value struct {
	Original   string // 原始值
	Normalized string // 规范化后的值
	Source     Source // 参数来源
	Rounds     int    // 实际解码轮数
	Truncated  bool   // 是否被截断
}

// Limits 解码限制
type Limits struct {
	MaxDecodeRounds int // 最大解码迭代次数
	MaxOutputBytes  int // 规范化输出最大字节数
}

// DefaultLimits 返回默认限制
func DefaultLimits() Limits {
	return Limits{
		MaxDecodeRounds: DefaultMaxDecodeRounds,
		MaxOutputBytes:  DefaultMaxOutputBytes,
	}
}

// Pipeline 规范化管线
type Pipeline struct {
	limits Limits
}

// New 构造规范化管线
func New(limits Limits) *Pipeline {
	if limits.MaxDecodeRounds <= 0 {
		limits.MaxDecodeRounds = DefaultMaxDecodeRounds
	}
	if limits.MaxOutputBytes <= 0 {
		limits.MaxOutputBytes = DefaultMaxOutputBytes
	}
	return &Pipeline{limits: limits}
}

// Normalize 对单个值执行完整规范化：URL解码 → HTML解码 → Unicode归一化 → 空白折叠
func (p *Pipeline) Normalize(raw string, source Source) Value {
	v := Value{Original: raw, Source: source}
	current := raw
	rounds := 0

	for i := 0; i < p.limits.MaxDecodeRounds; i++ {
		decoded := DecodeURL(current)
		decoded = DecodeHTMLEntities(decoded)
		decoded = NormalizeUnicode(decoded)
		decoded = StripZeroWidth(decoded)
		decoded = CollapseWhitespace(decoded)
		rounds++
		if decoded == current {
			break
		}
		current = decoded
	}

	if len(current) > p.limits.MaxOutputBytes {
		current = current[:p.limits.MaxOutputBytes]
		v.Truncated = true
	}
	v.Normalized = current
	v.Rounds = rounds
	return v
}

// NormalizeAll 批量规范化
func (p *Pipeline) NormalizeAll(inputs []TaggedInput) []Value {
	results := make([]Value, 0, len(inputs))
	for _, in := range inputs {
		results = append(results, p.Normalize(in.Raw, in.Source))
	}
	return results
}

// TaggedInput 带来源标记的原始输入
type TaggedInput struct {
	Raw    string
	Source Source
}

// CollectFromRequest 从请求上下文收集全部可检测参数
// 调用方需传入 reqctx 中已解析的参数，避免循环依赖
func CollectFromRequest(
	query map[string][]string,
	form map[string][]string,
	cookies map[string]string,
	headers map[string][]string,
	uri string,
	bodyValues []string,
) []TaggedInput {
	var inputs []TaggedInput

	for _, vs := range query {
		for _, v := range vs {
			inputs = append(inputs, TaggedInput{Raw: v, Source: SourceQuery})
		}
	}
	for _, vs := range form {
		for _, v := range vs {
			inputs = append(inputs, TaggedInput{Raw: v, Source: SourceForm})
		}
	}
	for _, v := range cookies {
		inputs = append(inputs, TaggedInput{Raw: v, Source: SourceCookie})
	}
	for _, vs := range headers {
		for _, v := range vs {
			inputs = append(inputs, TaggedInput{Raw: v, Source: SourceHeader})
		}
	}
	if uri != "" {
		inputs = append(inputs, TaggedInput{Raw: uri, Source: SourcePath})
	}
	for _, v := range bodyValues {
		inputs = append(inputs, TaggedInput{Raw: v, Source: SourceBody})
	}

	return inputs
}

// CollapseWhitespace 将连续空白折叠为单个空格
func CollapseWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
		} else {
			b.WriteRune(r)
			prevSpace = false
		}
	}
	return b.String()
}
