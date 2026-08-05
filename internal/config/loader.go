package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Load 从 YAML 文件加载静态配置，并应用环境变量覆盖
// 环境变量覆盖项：
//
//	JINGSHIELD_DB_PASS        -> Database.Pass
//	JINGSHIELD_DB_HOST        -> Database.Host
//	JINGSHIELD_DB_PORT        -> Database.Port
//	JINGSHIELD_DB_USER        -> Database.User
//	JINGSHIELD_DB_NAME        -> Database.Name
//	JINGSHIELD_UPSTREAM       -> Upstream.Target
//	JINGSHIELD_SESSION_KEY    -> Session.Secret
//	JINGSHIELD_LISTEN         -> Server.Listen
//	JINGSHIELD_TLS_LISTEN     -> Server.TLSListen
//	JINGSHIELD_TLS_CERT_FILE  -> Server.TLSCertFile
//	JINGSHIELD_TLS_KEY_FILE   -> Server.TLSKeyFile
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 应用环境变量覆盖（优先级高于文件，便于容器化部署注入密钥）
	applyEnvOverrides(&cfg)

	// 参数边界校验与默认值兜底
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// applyEnvOverrides 应用环境变量覆盖敏感/部署相关配置
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("JINGSHIELD_DB_PASS"); v != "" {
		cfg.Database.Pass = v
	}
	if v := os.Getenv("JINGSHIELD_DB_HOST"); v != "" {
		cfg.Database.Host = v
	}
	if v := os.Getenv("JINGSHIELD_DB_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Database.Port = p
		}
	}
	if v := os.Getenv("JINGSHIELD_DB_USER"); v != "" {
		cfg.Database.User = v
	}
	if v := os.Getenv("JINGSHIELD_DB_NAME"); v != "" {
		cfg.Database.Name = v
	}
	if v := os.Getenv("JINGSHIELD_UPSTREAM"); v != "" {
		cfg.Upstream.Target = v
	}
	if v := os.Getenv("JINGSHIELD_SESSION_KEY"); v != "" {
		cfg.Session.Secret = v
	}
	if v := os.Getenv("JINGSHIELD_LISTEN"); v != "" {
		cfg.Server.Listen = v
	}
	if v := os.Getenv("JINGSHIELD_TLS_LISTEN"); v != "" {
		cfg.Server.TLSListen = v
	}
	if v := os.Getenv("JINGSHIELD_TLS_CERT_FILE"); v != "" {
		cfg.Server.TLSCertFile = v
	}
	if v := os.Getenv("JINGSHIELD_TLS_KEY_FILE"); v != "" {
		cfg.Server.TLSKeyFile = v
	}
}

// validate 配置参数边界校验与默认值兜底
func (c *Config) validate() error {
	if c.Server.Listen == "" {
		c.Server.Listen = "127.0.0.1:18080"
	}
	if c.Server.AdminListen == "" {
		c.Server.AdminListen = c.Server.Listen
	}
	if c.Server.TLSListen != "" {
		if c.Server.TLSCertFile == "" || c.Server.TLSKeyFile == "" {
			return fmt.Errorf("启用 server.tls_listen 时必须同时配置 tls_cert_file 和 tls_key_file")
		}
		if c.Server.TLSListen == c.Server.Listen {
			return fmt.Errorf("server.tls_listen 不能与 server.listen 相同")
		}
	}
	if c.Server.ReadTimeout <= 0 {
		c.Server.ReadTimeout = 30
	}
	if c.Server.WriteTimeout <= 0 {
		c.Server.WriteTimeout = 30
	}
	if c.Server.MaxBodyBytes <= 0 {
		c.Server.MaxBodyBytes = 10 * 1024 * 1024
	}
	if c.Upstream.Target == "" {
		return fmt.Errorf("upstream.target 不能为空，请配置被保护站点地址")
	}
	if c.Upstream.Timeout <= 0 {
		c.Upstream.Timeout = 30
	}
	if c.Database.Host == "" {
		c.Database.Host = "127.0.0.1"
	}
	if c.Database.Port <= 0 {
		c.Database.Port = 3306
	}
	if c.Database.Charset == "" {
		c.Database.Charset = "utf8mb4"
	}
	if c.Database.MaxOpenConns <= 0 {
		c.Database.MaxOpenConns = 50
	}
	if c.Database.MaxIdleConns <= 0 {
		c.Database.MaxIdleConns = 10
	}
	if c.Database.ConnMaxLifetime <= 0 {
		c.Database.ConnMaxLifetime = 300
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Dir == "" {
		c.Log.Dir = "./logs"
	}
	if c.Log.MaxSizeMB <= 0 {
		c.Log.MaxSizeMB = 100
	}
	if c.Log.MaxBackups <= 0 {
		c.Log.MaxBackups = 10
	}
	if c.Log.MaxAgeDays <= 0 {
		c.Log.MaxAgeDays = 30
	}
	if c.Data.StateGCInterval <= 0 {
		c.Data.StateGCInterval = 60
	}
	if c.Session.Name == "" {
		c.Session.Name = "jingshield_session"
	}
	if c.Session.Secret == "" || c.Session.Secret == "change-me-to-a-random-32-byte-secret-key" {
		// 兜底随机密钥（仅本次进程有效），生产应显式配置
		secret, err := randomSecret()
		if err != nil {
			return fmt.Errorf("生成会话密钥失败: %w", err)
		}
		c.Session.Secret = secret
	}
	if c.Session.MaxAge <= 0 {
		c.Session.MaxAge = 7200
	}
	if c.Session.VerifyCookieMaxAge <= 0 {
		c.Session.VerifyCookieMaxAge = 3600
	}
	return nil
}

// randomSecret 生成兜底会话密钥（当用户未配置时）
func randomSecret() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(secret), nil
}

// DSN 生成 MySQL 连接 DSN
func (c *Config) DSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=true&loc=Local",
		c.Database.User, c.Database.Pass, c.Database.Host, c.Database.Port,
		c.Database.Name, c.Database.Charset)
}
