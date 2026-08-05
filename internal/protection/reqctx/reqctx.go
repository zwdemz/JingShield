package reqctx

// 请求上下文：单次 HTTP 请求的防护上下文
// 对应 PHP CCProtection::initRequestInfo() 收集的 ip/ua/uri/method/request_data
//
// 独立为叶子包，避免 protection/cc/detector/verify 之间形成导入环

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"jingshield/internal/pkg/iputil"
)

// RequestContext 请求防护上下文
type RequestContext struct {
	// 原始 HTTP 请求
	R *http.Request
	// 客户端 IP（经代理 header 解析后的真实 IP）
	IP string
	// User-Agent
	UserAgent string
	// 请求 URI（含 query）
	URI string
	// 请求方法
	Method string
	// GET 查询参数
	Get url.Values
	// POST 表单参数
	Post url.Values
	// 非表单请求体中的可检测文本。原始请求体会恢复后继续转发。
	BodyValues []string
	// Cookie
	Cookies []*http.Cookie
	// 请求头
	Header http.Header
	// 是否已通过 CC 验证（cc_verified cookie 存在且签名合法，签名校验由 verify 包完成）
	Verified bool
}

// NewRequestContext 从 HTTP 请求构建防护上下文
// 对应 PHP initRequestInfo() + getClientIP()
func NewRequestContext(r *http.Request, trustedProxies []string) (*RequestContext, error) {
	rc := &RequestContext{
		R:         r,
		IP:        iputil.GetClientIP(r, trustedProxies),
		UserAgent: r.Header.Get("User-Agent"),
		URI:       r.RequestURI,
		Method:    r.Method,
		Get:       r.URL.Query(),
		Header:    r.Header,
		Cookies:   r.Cookies(),
	}
	if r.Body == nil || r.Body == http.NoBody {
		return rc, nil
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("读取请求体失败: %w", err)
	}
	// WAF 读取请求体后必须恢复，否则 ReverseProxy 会向上游发送空 body。
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	mediaType, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch mediaType {
	case "application/x-www-form-urlencoded":
		if values, parseErr := url.ParseQuery(string(body)); parseErr == nil {
			rc.Post = values
		}
	case "multipart/form-data":
		if boundary := params["boundary"]; boundary != "" {
			rc.Post = readMultipartValues(body, boundary)
		}
	case "application/json":
		rc.BodyValues = jsonValues(body)
		// 同时保留原文，可检测跨字段拼接前的特征。
		rc.BodyValues = append(rc.BodyValues, string(body))
	default:
		if strings.HasPrefix(mediaType, "text/") || strings.Contains(mediaType, "xml") {
			rc.BodyValues = append(rc.BodyValues, string(body))
		}
	}
	return rc, nil
}

func readMultipartValues(body []byte, boundary string) url.Values {
	values := make(url.Values)
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		if part.FileName() == "" && part.FormName() != "" {
			value, _ := io.ReadAll(part)
			values.Add(part.FormName(), string(value))
		}
		_ = part.Close()
	}
	return values
}

func jsonValues(body []byte) []string {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for key, child := range x {
				out = append(out, key)
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		case string:
			out = append(out, x)
		}
	}
	walk(value)
	return out
}

// AllParamValues 收集全部请求参数值（GET + POST + Cookie）
// 用于 XSS/SQL 检测器遍历所有用户可控输入
func (rc *RequestContext) AllParamValues() []string {
	var values []string
	for _, vs := range rc.Get {
		values = append(values, vs...)
	}
	for _, vs := range rc.Post {
		values = append(values, vs...)
	}
	for _, c := range rc.Cookies {
		values = append(values, c.Value)
	}
	values = append(values, rc.BodyValues...)
	return values
}

// AllParamKeys 收集全部参数名（用于变异 CC 检测的参数名特征）
func (rc *RequestContext) AllParamKeys() []string {
	var keys []string
	for k := range rc.Get {
		keys = append(keys, k)
	}
	for k := range rc.Post {
		keys = append(keys, k)
	}
	return keys
}

// IsExcludedPath 判断是否在 CC 防护排除路径
// 对应 PHP checkCCAttack() 的 excluded_dirs 判断
func (rc *RequestContext) IsExcludedPath() bool {
	excluded := []string{"/admin/", "/api/", "/static/", "/images/", "/css/", "/js/", "/safe/", "/cc/"}
	for _, dir := range excluded {
		if strings.HasPrefix(rc.URI, dir) {
			return true
		}
	}
	return false
}
