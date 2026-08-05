package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"jingshield/internal/protection/reqctx"
)

func TestValidateRuleAndTargets(t *testing.T) {
	valid := RuleInput{Name: "admin path", Category: "access", Target: "uri", Pattern: `(?i)^/admin`, Action: ActionBlock, Enabled: true, Priority: 10}
	if _, err := ValidateRule(valid); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.Pattern = `secret(?=token)`
	if _, err := ValidateRule(invalid); err == nil || !strings.Contains(err.Error(), "RE2") {
		t.Fatalf("lookahead should be rejected, got %v", err)
	}

	rc := &reqctx.RequestContext{URI: "/search?q=needle", Method: http.MethodPost, Get: url.Values{"q": {"needle"}}, BodyValues: []string{"payload"}, Header: http.Header{"X-Test": {"marker"}}}
	for target, expected := range map[string]string{"uri": "/search", "args": "needle", "body": "payload", "headers": "marker", "method": "POST", "all": "needle"} {
		if !strings.Contains(targetValue(target, rc), expected) {
			t.Errorf("target %s did not contain %q", target, expected)
		}
	}
}

func TestValidatePublicURLRejectsPrivateTargets(t *testing.T) {
	for _, raw := range []string{"http://example.com/rules", "https://127.0.0.1/rules", "https://[::1]/rules", "https://user@example.com/rules"} {
		if err := validatePublicURL(context.Background(), raw); err == nil {
			t.Errorf("accepted unsafe update URL %q", raw)
		}
	}
}

func TestDecodeBase64Variants(t *testing.T) {
	for _, value := range []string{"AQID", "AQIDBA=="} {
		if data, err := decodeBase64(value); err != nil || len(data) < 3 {
			t.Fatalf("decode %q: %v", value, err)
		}
	}
}

func TestBundledJavaEmergencyPack(t *testing.T) {
	raw, err := os.ReadFile("../../rules/packs/java-emergency-2026h1.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack RulePack
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	if pack.Schema != "jingshield.rules/v1" || pack.Version != "java-emergency-2026h1.1" || len(pack.Rules) != 11 {
		t.Fatalf("unexpected pack metadata: schema=%q version=%q rules=%d", pack.Schema, pack.Version, len(pack.Rules))
	}
	for _, input := range pack.Rules {
		if _, err := ValidateRule(input); err != nil {
			t.Errorf("rule %q: %v", input.Name, err)
		}
	}

	fastjson := regexp.MustCompile(pack.Rules[0].Pattern)
	if !fastjson.MatchString(`{"@type":"jar:file:sample"}`) {
		t.Fatal("fastjson URL-special type rule did not match the regression sample")
	}
	if fastjson.MatchString(`{"@type":"com.example.SafeDto"}`) {
		t.Fatal("fastjson URL-special type rule matched an ordinary type name")
	}
	partialPUT := regexp.MustCompile(pack.Rules[7].Pattern)
	if !partialPUT.MatchString("/upload\nPUT\n\nbody\nContent-Range: bytes 0-9/10") {
		t.Fatal("partial PUT rule did not match the normalized request sample")
	}
}
