package config

import (
	"context"
	"database/sql"
	"strconv"
	"sync"
	"time"
)

// DynamicConfig 动态配置：从 jyj_config 表加载，支持热加载
// 对应 PHP CCProtection::loadConfigs() 的 jyj_config 读取逻辑
// 后台修改配置后调用 Reload() 即时生效，无需重启进程
type DynamicConfig struct {
	db *sql.DB
	mu sync.RWMutex
	m  map[string]string
}

// 默认动态配置（数据库不可用或表不存在时的兜底，对应 PHP 默认配置）
var defaultDynamicConfig = map[string]string{
	"system_status":                  "1",    // 系统总开关 1=启用 0=禁用
	"cc_protection_status":           "1",    // CC 防护开关
	"cc_visit_count":                 "100",  // CC 触发次数
	"cc_visit_time":                  "60",   // CC 触发时间窗口（秒）
	"cc_blacklist_time":              "3600", // 临时黑名单时长（秒）
	"cc_verify_fail_limit":           "10",   // 验证失败次数上限
	"cc_whitelist_time":              "1800", // 验证通过后白名单时长（秒）
	"cc_verification_mode":           "1",    // 验证模式 1-8
	"xss_protection_status":          "1",    // XSS 防护开关
	"sql_protection_status":          "1",    // SQL 注入防护开关
	"file_check_status":              "0",    // 文件校验开关
	"log_keep_days":                  "30",   // 日志保留天数
	"error_output_format":            "json", // 错误输出格式 json/html
	"oversea_ip_status":              "0",    // 海外 IP 拦截开关
	"api_enabled":                    "1",    // 外部设备联动 API 开关
	"alert_cpu_percent":              "80",   // CPU 使用率告警阈值
	"alert_memory_percent":           "85",   // 内存使用率告警阈值
	"alert_disk_percent":             "85",   // 磁盘使用率告警阈值
	"alert_log_size_mb":              "512",  // 日志目录大小告警阈值
	"alert_request_rate":             "600",  // 业务请求速率告警阈值（请求/分钟）
	"device_auto_block_enabled":      "0",
	"device_auto_block_severity":     "8",
	"device_auto_block_seconds":      "3600",
	"policy_auto_update":             "0",
	"policy_update_url":              "",
	"policy_update_interval_minutes": "360",
	"policy_update_public_key":       "",
	"policy_last_version":            "",
	"policy_last_update":             "",
	"policy_last_error":              "",
}

// NewDynamicConfig 创建动态配置实例
func NewDynamicConfig(db *sql.DB) *DynamicConfig {
	return &DynamicConfig{
		db: db,
		m:  make(map[string]string),
	}
}

// Load 从数据库加载全部配置；数据库不可用时使用默认值兜底
func (d *DynamicConfig) Load(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 先装入默认配置作为兜底
	cfg := make(map[string]string, len(defaultDynamicConfig))
	for k, v := range defaultDynamicConfig {
		cfg[k] = v
	}

	if d.db == nil {
		d.m = cfg
		return nil
	}

	// 检查表是否存在（对应 PHP SHOW TABLES LIKE 'jyj_config'）
	var tbl string
	err := d.db.QueryRowContext(ctx, "SHOW TABLES LIKE 'jyj_config'").Scan(&tbl)
	if err != nil {
		// 表不存在或查询失败，使用默认配置
		d.m = cfg
		return nil
	}

	// 加载全部配置键值
	rows, err := d.db.QueryContext(ctx, "SELECT config_key, config_value FROM jyj_config")
	if err != nil {
		d.m = cfg
		return nil
	}
	defer rows.Close()

	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			continue
		}
		cfg[k] = v
	}

	d.m = cfg
	return nil
}

// Reload 重新加载配置（热加载）
func (d *DynamicConfig) Reload(ctx context.Context) error {
	return d.Load(ctx)
}

// StartAutoReload 启动后台定时热加载（每 reloadInterval 刷新一次）
func (d *DynamicConfig) StartAutoReload(ctx context.Context, reloadInterval time.Duration) {
	go func() {
		ticker := time.NewTicker(reloadInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = d.Reload(ctx)
			}
		}
	}()
}

// Get 获取字符串配置值，不存在返回空串
func (d *DynamicConfig) Get(key string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.m[key]
}

// GetDefault 获取字符串配置值，不存在返回默认值
func (d *DynamicConfig) GetDefault(key, def string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if v, ok := d.m[key]; ok {
		return v
	}
	return def
}

// GetInt 获取整型配置值
func (d *DynamicConfig) GetInt(key string) int {
	v := d.Get(key)
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

// GetIntDefault 获取整型配置值，不存在或非法返回默认值
func (d *DynamicConfig) GetIntDefault(key string, def int) int {
	v := d.Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// GetBool 获取布尔型配置值（"1"=true）
func (d *DynamicConfig) GetBool(key string) bool {
	return d.GetInt(key) != 0
}

// All 返回全部配置的副本（用于后台展示）
func (d *DynamicConfig) All() map[string]string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make(map[string]string, len(d.m))
	for k, v := range d.m {
		out[k] = v
	}
	return out
}

// Set 更新单条配置（写库 + 更新内存）
func (d *DynamicConfig) Set(ctx context.Context, key, value string) error {
	if d.db == nil {
		return ErrDBUnavailable
	}
	// INSERT ... ON DUPLICATE KEY UPDATE，对应 PHP setConfig() 的 SQL
	_, err := d.db.ExecContext(ctx,
		"INSERT INTO jyj_config (config_key, config_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE config_value = ?",
		key, value, value)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.m[key] = value
	d.mu.Unlock()
	return nil
}

// ErrDBUnavailable 数据库不可用错误
var ErrDBUnavailable = errDBUnavailable{}

type errDBUnavailable struct{}

func (errDBUnavailable) Error() string { return "数据库不可用" }
