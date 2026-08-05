package normalize

// Unicode 归一化
// - NFKC 兼容性分解：全角字符 → 半角、组合字符 → 等价形式
// - 零宽字符剥离：U+200B~U+200F、U+FEFF、U+2028~U+202E 等不可见字符
// - 不引入外部依赖（golang.org/x/text/unicode/norm 已在 go.mod 的间接依赖中）

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// NormalizeUnicode NFKC 归一化 + 全角半角转换
func NormalizeUnicode(s string) string {
	if isASCIIOnly(s) {
		return s
	}
	normalized := norm.NFKC.String(s)
	return normalized
}

// StripZeroWidth 剥离零宽和不可见格式化字符
func StripZeroWidth(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isZeroWidth(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isZeroWidth 判断是否为零宽/不可见格式化字符
func isZeroWidth(r rune) bool {
	switch r {
	case '\u200B', // ZERO WIDTH SPACE
		'\u200C', // ZERO WIDTH NON-JOINER
		'\u200D', // ZERO WIDTH JOINER
		'\u200E', // LEFT-TO-RIGHT MARK
		'\u200F', // RIGHT-TO-LEFT MARK
		'\u202A', // LEFT-TO-RIGHT EMBEDDING
		'\u202B', // RIGHT-TO-LEFT EMBEDDING
		'\u202C', // POP DIRECTIONAL FORMATTING
		'\u202D', // LEFT-TO-RIGHT OVERRIDE
		'\u202E', // RIGHT-TO-LEFT OVERRIDE
		'\u2060', // WORD JOINER
		'\u2061', // FUNCTION APPLICATION
		'\u2062', // INVISIBLE TIMES
		'\u2063', // INVISIBLE SEPARATOR
		'\u2064', // INVISIBLE PLUS
		'\uFEFF', // ZERO WIDTH NO-BREAK SPACE (BOM)
		'\u00AD': // SOFT HYPHEN
		return true
	}
	if unicode.Is(unicode.Cf, r) {
		return true
	}
	return false
}

func isASCIIOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7F {
			return false
		}
	}
	return true
}
