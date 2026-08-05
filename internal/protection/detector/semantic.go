package detector

// 语义检测器：路径穿越、SSRF、XXE
// 使用 normalize 包的多层解码管线作为预处理，对规范化后的值执行结构化检测

import (
	"context"
	"strings"

	"jingshield/internal/model"
	"jingshield/internal/pkg/errx"
	"jingshield/internal/protection/normalize"
	"jingshield/internal/protection/reqctx"
)

var semanticPipeline = normalize.New(normalize.DefaultLimits())

// PathTraversalDetector 路径穿越检测器
type PathTraversalDetector struct{}

func NewPathTraversalDetector() *PathTraversalDetector { return &PathTraversalDetector{} }

func (d *PathTraversalDetector) Name() string { return "PathTraversal" }

func (d *PathTraversalDetector) Check(_ context.Context, rc *reqctx.RequestContext) *Result {
	inputs := collectSemanticInputs(rc)
	for _, nv := range inputs {
		r := normalize.DetectPathTraversal(nv.Normalized)
		if r.Detected {
			return &Result{
				Detected:   true,
				AttackType: model.AttackTypePathTraversal,
				Detail:     r.Detail,
				Code:       errx.CodePathTraversal,
			}
		}
	}
	return nil
}

// SSRFDetector SSRF URL 检测器
type SSRFDetector struct{}

func NewSSRFDetector() *SSRFDetector { return &SSRFDetector{} }

func (d *SSRFDetector) Name() string { return "SSRF" }

func (d *SSRFDetector) Check(_ context.Context, rc *reqctx.RequestContext) *Result {
	inputs := collectSemanticInputs(rc)
	for _, nv := range inputs {
		if !looksLikeURL(nv.Normalized) {
			continue
		}
		r := normalize.DetectSSRF(nv.Normalized)
		if r.Detected {
			return &Result{
				Detected:   true,
				AttackType: model.AttackTypeSSRF,
				Detail:     r.Detail,
				Code:       errx.CodeSSRF,
			}
		}
	}
	return nil
}

// XXEDetector XXE/XML 注入检测器
type XXEDetector struct{}

func NewXXEDetector() *XXEDetector { return &XXEDetector{} }

func (d *XXEDetector) Name() string { return "XXE" }

func (d *XXEDetector) Check(_ context.Context, rc *reqctx.RequestContext) *Result {
	inputs := collectSemanticInputs(rc)
	for _, nv := range inputs {
		if !looksLikeXML(nv.Normalized) {
			continue
		}
		r := normalize.DetectXXE(nv.Normalized)
		if r.Detected {
			return &Result{
				Detected:   true,
				AttackType: model.AttackTypeXXE,
				Detail:     r.Detail,
				Code:       errx.CodeXXE,
			}
		}
	}
	return nil
}

// collectSemanticInputs 收集请求中全部可检测参数并规范化
func collectSemanticInputs(rc *reqctx.RequestContext) []normalize.Value {
	cookies := make(map[string]string, len(rc.Cookies))
	for _, c := range rc.Cookies {
		cookies[c.Name] = c.Value
	}
	tagged := normalize.CollectFromRequest(
		rc.Get, rc.Post, cookies, rc.Header, rc.URI, rc.BodyValues,
	)
	return semanticPipeline.NormalizeAll(tagged)
}

// looksLikeURL 快速判断值是否可能包含 URL（避免对每个参数都做 URL 解析）
func looksLikeURL(s string) bool {
	return strings.Contains(s, "://") ||
		strings.Contains(s, ":/") ||
		strings.HasPrefix(s, "//") ||
		strings.Contains(s, ".com") ||
		strings.Contains(s, ".net") ||
		strings.Contains(s, ".org") ||
		strings.Contains(s, ".io") ||
		strings.Contains(s, ".cn")
}

// looksLikeXML 快速判断值是否可能包含 XML
func looksLikeXML(s string) bool {
	return strings.Contains(s, "<?xml") ||
		strings.Contains(s, "<!DOCTYPE") ||
		strings.Contains(s, "<!ENTITY") ||
		strings.Contains(s, "xi:include") ||
		strings.Contains(s, "<!doctype")
}
