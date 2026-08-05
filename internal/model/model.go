package model

// 实体模型层，对应数据库业务表
// 命名与表字段对齐，使用标准 Go 命名风格，JSON tag 对齐 API 输出

import "time"

// Config 系统配置表 jyj_config
type Config struct {
	ID          int64     `json:"id"          db:"id"`
	ConfigKey   string    `json:"config_key"  db:"config_key"`
	ConfigValue string    `json:"config_value" db:"config_value"`
	ConfigDesc  string    `json:"config_desc" db:"config_desc"`
	CreatedAt   time.Time `json:"created_at"  db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"  db:"updated_at"`
}

// Site 防护站点表 jyj_sites。Host 支持精确域名/IP，以及 *.example.com
// 形式的单级或多级子域通配；Upstream 是实际业务源站地址。
type Site struct {
	ID            int64     `json:"id"            db:"id"`
	Name          string    `json:"name"          db:"name"`
	Host          string    `json:"host"          db:"host"`
	Upstream      string    `json:"upstream"      db:"upstream"`
	Enabled       bool      `json:"enabled"       db:"enabled"`
	PassHost      bool      `json:"pass_host"     db:"pass_host"`
	TLSSkipVerify bool      `json:"tls_skip_verify" db:"tls_skip_verify"`
	CreatedAt     time.Time `json:"created_at"    db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"    db:"updated_at"`
}

// PolicyRule 可热加载的自定义防护策略。
type PolicyRule struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Target      string    `json:"target"`
	Pattern     string    `json:"pattern"`
	Action      int       `json:"action"` // 1=拦截 2=仅记录
	Enabled     bool      `json:"enabled"`
	Priority    int       `json:"priority"`
	Source      string    `json:"source"` // custom/import/auto
	Version     string    `json:"version"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// DeviceEvent 外部安全设备上报后归一化的事件。
type DeviceEvent struct {
	ID          int64     `json:"id"`
	DeviceName  string    `json:"device_name"`
	Vendor      string    `json:"vendor"`
	Format      string    `json:"format"`
	SourceIP    string    `json:"source_ip"`
	EventType   string    `json:"event_type"`
	Severity    int       `json:"severity"`
	EventIP     string    `json:"event_ip"`
	Message     string    `json:"message"`
	RawJSON     string    `json:"-"`
	ActionTaken string    `json:"action_taken"`
	CreatedAt   time.Time `json:"created_at"`
}

// IPListType IP 名单类型枚举
const (
	IPTypeWhitelist     = 1 // 白名单
	IPTypeBlacklist     = 2 // 黑名单（永久）
	IPTypeTempBlacklist = 3 // 临时黑名单（带过期）
)

// IPList IP 黑白名单表 jyj_ip_list
type IPList struct {
	ID         int64      `json:"id"          db:"id"`
	IP         string     `json:"ip"          db:"ip"`
	Type       int        `json:"type"        db:"type"` // 1=白名单 2=黑名单 3=临时黑名单
	Reason     string     `json:"reason"      db:"reason"`
	ExpireTime *time.Time `json:"expire_time" db:"expire_time"` // 仅临时黑名单有效
	CreatedAt  time.Time  `json:"created_at"  db:"created_at"`
}

// AttackLog 攻击日志表 jyj_attack_log
type AttackLog struct {
	ID           int64     `json:"id"            db:"id"`
	IP           string    `json:"ip"            db:"ip"`
	IPLocation   string    `json:"ip_location"   db:"ip_location"`
	Host         string    `json:"host"          db:"host"`
	URI          string    `json:"uri"           db:"uri"`
	Method       string    `json:"method"        db:"method"`
	AttackType   string    `json:"attack_type"   db:"attack_type"`
	AttackDetail string    `json:"attack_detail" db:"attack_detail"`
	AttackCount  int       `json:"attack_count"  db:"attack_count"`
	Status       int       `json:"status"        db:"status"` // 1=已拦截 2=已放行
	CreatedAt    time.Time `json:"created_at"    db:"created_at"`
}

// AccessLog 访问日志表 jyj_access_log
type AccessLog struct {
	ID           int64     `json:"id"            db:"id"`
	IP           string    `json:"ip"            db:"ip"`
	Host         string    `json:"host"          db:"host"`
	URI          string    `json:"uri"           db:"uri"`
	Method       string    `json:"method"        db:"method"`
	UserAgent    string    `json:"user_agent"    db:"user_agent"`
	Referer      string    `json:"referer"       db:"referer"`
	Status       int       `json:"status"        db:"status"`
	ResponseTime float64   `json:"response_time" db:"response_time"`
	CreatedAt    time.Time `json:"created_at"    db:"created_at"`
}

// FileCheck 文件校验表 jyj_file_check
type FileCheck struct {
	ID            int64     `json:"id"              db:"id"`
	FilePath      string    `json:"file_path"       db:"file_path"`
	Hash          string    `json:"hash"            db:"hash"`
	LastCheckTime time.Time `json:"last_check_time" db:"last_check_time"`
	Status        int       `json:"status"          db:"status"` // 1=正常 2=异常
}

// User 用户管理表 jyj_users
type User struct {
	ID                 int64      `json:"id"                   db:"id"`
	Username           string     `json:"username"             db:"username"`
	Password           string     `json:"-"                    db:"password"` // 不输出
	Email              string     `json:"email"                db:"email"`
	Status             int        `json:"status"               db:"status"` // 1=启用 0=禁用
	MustChangePassword bool       `json:"must_change_password" db:"must_change_password"`
	LastLoginAt        *time.Time `json:"last_login_at"        db:"last_login_at"`
	CreatedAt          time.Time  `json:"created_at"           db:"created_at"`
}

// URLRule URL 过滤规则表 jyj_url_rules
type URLRule struct {
	ID         int64     `json:"id"          db:"id"`
	URLPattern string    `json:"url_pattern" db:"url_pattern"`
	Action     int       `json:"action"      db:"action"` // 1=允许 2=阻止
	CreatedAt  time.Time `json:"created_at"  db:"created_at"`
}

// VerifyFail 验证失败次数表 jyj_verify_fail
type VerifyFail struct {
	ID           int64     `json:"id"             db:"id"`
	IP           string    `json:"ip"             db:"ip"`
	FailCount    int       `json:"fail_count"     db:"fail_count"`
	LastFailTime time.Time `json:"last_fail_time" db:"last_fail_time"`
	CreatedAt    time.Time `json:"created_at"     db:"created_at"`
}

// LoginLog 登录日志表 jyj_login_log
type LoginLog struct {
	ID        int64     `json:"id"         db:"id"`
	UserID    int64     `json:"user_id"    db:"user_id"`
	LoginIP   string    `json:"login_ip"   db:"login_ip"`
	LoginTime time.Time `json:"login_time" db:"login_time"`
}

// 攻击类型常量（对应 logAttack 的 attack_type 入参）
const (
	AttackTypeCC           = "CC攻击"
	AttackTypeXSS          = "XSS攻击"
	AttackTypeSQL          = "SQL注入"
	AttackTypeBlacklist    = "IP黑名单"
	AttackTypeOversea      = "海外IP拦截"
	AttackTypeShieldBypass = "穿盾攻击"
	AttackTypeVerifyFail   = "验证失败次数过多"
	AttackTypePolicy       = "自定义策略"
)
