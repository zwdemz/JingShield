package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestAllBundledRulePacksValidate(t *testing.T) {
	files, err := filepath.Glob("../../rules/packs/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 2 {
		t.Fatalf("expected at least two bundled rule packs, got %d", len(files))
	}
	for _, filename := range files {
		filename := filename
		t.Run(filepath.Base(filename), func(t *testing.T) {
			pack := loadBundledPack(t, filename)
			if pack.Schema != "jingshield.rules/v1" || !validRulePackVersion(pack.Version) || len(pack.Rules) == 0 || len(pack.Rules) > 5000 {
				t.Fatalf("invalid pack metadata: schema=%q version=%q rules=%d", pack.Schema, pack.Version, len(pack.Rules))
			}
			names := make(map[string]struct{}, len(pack.Rules))
			for _, input := range pack.Rules {
				if _, err := ValidateRule(input); err != nil {
					t.Errorf("rule %q: %v", input.Name, err)
				}
				key := strings.ToLower(input.Name)
				if _, exists := names[key]; exists {
					t.Errorf("duplicate rule name %q", input.Name)
				}
				names[key] = struct{}{}
			}
		})
	}
}

func TestBaselinePackRegressionSamples(t *testing.T) {
	pack := loadBundledPack(t, "../../rules/packs/jingshield-baseline-2026.08.json")
	rules := make(map[string]RuleInput, len(pack.Rules))
	maxBlockPriority, minLogPriority := 0, 10001
	for _, rule := range pack.Rules {
		rules[rule.Name] = rule
		if rule.Action == ActionBlock && rule.Priority > maxBlockPriority {
			maxBlockPriority = rule.Priority
		}
		if rule.Action == ActionLog && rule.Priority < minLogPriority {
			minLogPriority = rule.Priority
		}
	}
	if minLogPriority <= maxBlockPriority {
		t.Fatalf("log-only rule priority %d can mask a later blocking rule (max block priority %d)", minLogPriority, maxBlockPriority)
	}

	cases := []struct {
		name     string
		positive string
		negative string
	}{
		{"SQL 时间盲注函数", "1 AND pg_sleep(3)", "sleep quality report"},
		{"NoSQL 服务端脚本操作符", `{"$where":"this.active"}`, `{"where":"office"}`},
		{"Shell 分隔符命令注入", "name; curl http://example.test", "red; blue"},
		{"编码 HTML 活动标签", "%3Csvg onload=alert(1)", "percentage 3c script"},
		{"编码与双重编码路径穿越", "%252e%252e%252fetc/passwd", "/images/profile.png"},
		{"SSRF 内网 IPv4 目标", "http://192.168.10.20/admin", "https://www.example.com/"},
		{"XXE DOCTYPE 实体声明", `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>`, `<document><entity>safe</entity></document>`},
		{"Jinja Twig 模板执行链", `{{ ''.__class__.__mro__ }}`, `Hello {{ display_name }}`},
		{"JavaScript 原型污染键", `{"__proto__":{"admin":true}}`, `{"prototype_name":"v1"}`},
		{"上传服务端脚本扩展名", `{"__jingshield_upload__":true,"filename":"avatar.jpg.php"}`, `{"__jingshield_upload__":true,"filename":"avatar.jpg"}`},
		{"上传文件名路径与空字节", `{"__jingshield_upload__":true,"filename":"../shell.txt"}`, `{"__jingshield_upload__":true,"filename":"notes.txt"}`},
		{"上传声明类型与内容不一致审计", `{"__jingshield_upload__":true,"filename":"a.jpg","type_mismatch":true}`, `{"__jingshield_upload__":true,"filename":"a.jpg","type_mismatch":false}`},
		{"上传内容包含服务端脚本", "__jingshield_upload_sample__:<?php echo 1; ?>", "__jingshield_upload_sample__:plain text"},
		{"GraphQL Introspection 审计", `{"query":"query Probe { __schema { types { name } } }"}`, `{"query":"query Product { product { name } }"}`},
		{"GraphQL JSON 批处理审计", `[{"query":"query A { viewer { id } }"}]`, `{"query":"query A { viewer { id } }"}`},
		{"GraphQL 高深度查询审计", `query { a { b { c { d { e { f { g { h } } } } } } } }`, `query { viewer { id } }`},
		{"GraphQL 别名放大审计", `query { a1:x a2:x a3:x a4:x a5:x a6:x a7:x a8:x a9:x a10:x a11:x a12:x }`, `query { first:x second:y }`},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			rule, ok := rules[test.name]
			if !ok {
				t.Fatalf("rule not found")
			}
			re := regexp.MustCompile(rule.Pattern)
			if !re.MatchString(test.positive) {
				t.Errorf("did not match positive sample %q", test.positive)
			}
			if re.MatchString(test.negative) {
				t.Errorf("matched negative sample %q", test.negative)
			}
		})
	}
}

func loadBundledPack(t *testing.T, filename string) RulePack {
	t.Helper()
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var pack RulePack
	if err := decodeStrictJSON(raw, &pack); err != nil {
		t.Fatal(err)
	}
	return pack
}
