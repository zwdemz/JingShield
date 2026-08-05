package normalize

// HTML 实体解码器
// 覆盖命名实体（&amp; &lt; &gt; &quot; 等）和数字实体（&#60; &#x3c;）
// 不使用 html.UnescapeString 是为了控制解码深度和阻止危险实体

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// namedEntities 常用 HTML 命名实体映射
var namedEntities = map[string]string{
	"amp":    "&",
	"lt":     "<",
	"gt":     ">",
	"quot":   "\"",
	"apos":   "'",
	"nbsp":   " ",
	"iexcl":  "\u00a1",
	"cent":   "\u00a2",
	"pound":  "\u00a3",
	"curren": "\u00a4",
	"yen":    "\u00a5",
	"brvbar": "\u00a6",
	"sect":   "\u00a7",
	"uml":    "\u00a8",
	"copy":   "\u00a9",
	"ordf":   "\u00aa",
	"laquo":  "\u00ab",
	"not":    "\u00ac",
	"shy":    "\u00ad",
	"reg":    "\u00ae",
	"macr":   "\u00af",
	"deg":    "\u00b0",
	"plusmn": "\u00b1",
	"sup2":   "\u00b2",
	"sup3":   "\u00b3",
	"acute":  "\u00b4",
	"micro":  "\u00b5",
	"para":   "\u00b6",
	"middot": "\u00b7",
	"cedil":  "\u00b8",
	"sup1":   "\u00b9",
	"ordm":   "\u00ba",
	"raquo":  "\u00bb",
	"frac14": "\u00bc",
	"frac12": "\u00bd",
	"frac34": "\u00be",
	"iquest": "\u00bf",
	"times":  "\u00d7",
	"divide": "\u00f7",
	"tab":    "\t",
	"newline": "\n",
}

// DecodeHTMLEntities 解码 HTML 实体，无效实体保留原文
func DecodeHTMLEntities(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] != '&' {
			b.WriteByte(s[i])
			i++
			continue
		}
		end := strings.IndexByte(s[i:], ';')
		if end < 0 || end > 12 {
			b.WriteByte(s[i])
			i++
			continue
		}
		entity := s[i+1 : i+end]
		var decoded string
		if len(entity) > 1 && entity[0] == '#' {
			decoded = decodeNumericEntity(entity[1:])
		} else {
			decoded = namedEntities[entity]
		}
		if decoded != "" {
			b.WriteString(decoded)
			i += end + 1
		} else {
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

// decodeNumericEntity 解码数字实体 &#DDDD; 或 &#xHHHH;
func decodeNumericEntity(body string) string {
	var v uint64
	var err error
	if len(body) > 1 && (body[0] == 'x' || body[0] == 'X') {
		v, err = strconv.ParseUint(body[1:], 16, 32)
	} else {
		v, err = strconv.ParseUint(body, 10, 32)
	}
	if err != nil || v == 0 || v > 0x10FFFF {
		return ""
	}
	r := rune(v)
	if !utf8.ValidRune(r) {
		r = '\uFFFD'
	}
	return string(r)
}
