package config

// 静态配置结构定义，对应 configs/config.yaml
// 仅启动时加载，修改需重启或执行 reload 命令

// Config 根配置
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Upstream UpstreamConfig `yaml:"upstream"`
	Database DatabaseConfig `yaml:"database"`
	AdminIPs []string       `yaml:"admin_ips"`
	Log      LogConfig      `yaml:"log"`
	Data     DataConfig     `yaml:"data"`
	Session  SessionConfig  `yaml:"session"`
}

// ServerConfig 服务监听配置
type ServerConfig struct {
	Listen       string `yaml:"listen"`
	AdminListen  string `yaml:"admin_listen"`
	TLSListen    string `yaml:"tls_listen"`
	TLSCertFile  string `yaml:"tls_cert_file"`
	TLSKeyFile   string `yaml:"tls_key_file"`
	ReadTimeout  int    `yaml:"read_timeout"`
	WriteTimeout int    `yaml:"write_timeout"`
	MaxBodyBytes int64  `yaml:"max_body_bytes"`
	// TrustedProxies lists reverse proxies/CDNs whose forwarding headers may be trusted.
	// Entries may be individual IP addresses or CIDR ranges. When empty, forwarding
	// headers are ignored and RemoteAddr is always used as the client address.
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// UpstreamConfig 反向代理目标配置
type UpstreamConfig struct {
	Target   string `yaml:"target"`
	Timeout  int    `yaml:"timeout"`
	PassHost bool   `yaml:"pass_host"`
}

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	Host            string `yaml:"host"`
	Port            int    `yaml:"port"`
	User            string `yaml:"user"`
	Pass            string `yaml:"pass"`
	Name            string `yaml:"name"`
	Charset         string `yaml:"charset"`
	MaxOpenConns    int    `yaml:"max_open_conns"`
	MaxIdleConns    int    `yaml:"max_idle_conns"`
	ConnMaxLifetime int    `yaml:"conn_max_lifetime"`
}

// LogConfig 日志配置
type LogConfig struct {
	Level      string `yaml:"level"`
	Dir        string `yaml:"dir"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAgeDays int    `yaml:"max_age_days"`
}

// DataConfig 数据/缓存目录配置
type DataConfig struct {
	QQWryDat        string `yaml:"qqwry_dat"`
	StateGCInterval int    `yaml:"state_gc_interval"`
}

// SessionConfig 会话与 cookie 配置
type SessionConfig struct {
	Name               string `yaml:"name"`
	Secret             string `yaml:"secret"`
	MaxAge             int    `yaml:"max_age"`
	Domain             string `yaml:"domain"`
	Secure             bool   `yaml:"secure"`
	VerifyCookieMaxAge int    `yaml:"verify_cookie_max_age"`
}
