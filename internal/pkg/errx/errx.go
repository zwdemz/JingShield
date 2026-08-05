package errx

// 全局统一错误码定义
// 对应原系统的 outputError(code, message) 错误码体系
// 规则：负数为错误，0 或正数为成功

const (
	CodeSuccess      = 0    // 成功
	CodeInternal     = -1   // 系统内部错误
	CodeDBError      = -2   // 数据库错误
	CodeParamInvalid = -3   // 参数校验失败
	CodeUnauthorized = -401 // 未登录/未授权
	CodeForbidden    = -403 // 无权访问
	CodeNotFound     = -404 // 资源不存在

	// 防护相关错误码（与原系统对齐）
	CodeSQLInjection = -100 // SQL 注入命中
	CodeXSSAttack    = -110 // XSS 命中
	CodeVerifyFail   = -112 // 验证失败次数过多
	CodeBlacklisted  = -113 // IP 黑名单
	CodeOversea      = -114 // 海外 IP 拦截
	CodeCCAttack     = -115 // CC 攻击
	CodePolicyAttack = -120 // 自定义策略命中

	// 语义检测相关错误码（P0 阶段）
	CodePathTraversal = -130 // 路径穿越命中
	CodeSSRF          = -131 // SSRF 命中
	CodeXXE           = -132 // XXE 命中
)

// Error 统一业务错误，携带错误码与提示信息
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

// New 构造业务错误
func New(code int, message string) *Error {
	return &Error{Code: code, Message: message}
}

// 预置常用错误
var (
	ErrInternal     = New(CodeInternal, "系统内部错误")
	ErrDB           = New(CodeDBError, "数据库错误")
	ErrParam        = New(CodeParamInvalid, "参数校验失败")
	ErrUnauthorized = New(CodeUnauthorized, "未登录或登录已过期")
	ErrForbidden    = New(CodeForbidden, "无权访问")
	ErrNotFound     = New(CodeNotFound, "资源不存在")
)

// Wrap 将普通 error 包装为业务错误
func Wrap(code int, err error) *Error {
	if err == nil {
		return nil
	}
	return &Error{Code: code, Message: err.Error()}
}
