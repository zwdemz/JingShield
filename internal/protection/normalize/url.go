package normalize

// URL 多层解码器
// 有界迭代：百分号解码 → Unicode 解码（%uXXXX）→ 十六进制解码（0xXX）
// 每轮检测是否发生变化，收敛后停止，防止无限循环

import (
	"strconv"
	"strings"
)

// DecodeURL 对字符串执行多层 URL 解码，直到收敛或达到安全上限
func DecodeURL(s string) string {
	prev := ""
	current := s
	for i := 0; i < 5 && current != prev; i++ {
		prev = current
		current = percentDecode(current)
		current = unicodePercentDecode(current)
		current = hexPrefixDecode(current)
	}
	return current
}

// percentDecode 标准百分号解码（%XX），无效序列保留原文
func percentDecode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := hexVal(s[i+1])
			lo, ok2 := hexVal(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 3
				continue
			}
		}
		if s[i] == '+' {
			b.WriteByte(' ')
			i++
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// unicodePercentDecode 解码 %uXXXX 格式（IE/旧式编码）
func unicodePercentDecode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if i+5 < len(s) && s[i] == '%' && (s[i+1] == 'u' || s[i+1] == 'U') {
			if v, err := strconv.ParseUint(s[i+2:i+6], 16, 32); err == nil {
				b.WriteRune(rune(v))
				i += 6
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// hexPrefixDecode 解码 0xXX 格式（仅解码可打印 ASCII，避免破坏 URL 中的 IP 数字格式）
func hexPrefixDecode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if i+3 < len(s) && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X') {
			hi, ok1 := hexVal(s[i+2])
			lo, ok2 := hexVal(s[i+3])
			if ok1 && ok2 {
				decoded := byte(hi<<4 | lo)
				if decoded >= 0x20 && decoded <= 0x7E {
					b.WriteByte(decoded)
					i += 4
					continue
				}
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func hexVal(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	default:
		return 0, false
	}
}
