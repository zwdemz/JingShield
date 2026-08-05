package repository

import (
	"context"
	"database/sql"
	"fmt"
)

type migration struct {
	name string
	sql  string
}

// schemaMigrations intentionally use CREATE TABLE IF NOT EXISTS and idempotent
// seed statements. Running migrate repeatedly is safe and never removes data.
var schemaMigrations = []migration{
	{"jyj_policy_rules", `CREATE TABLE IF NOT EXISTS jyj_policy_rules (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(100) NOT NULL,
  category VARCHAR(50) NOT NULL DEFAULT 'custom',
  target VARCHAR(20) NOT NULL DEFAULT 'all',
  pattern VARCHAR(1000) NOT NULL,
  action TINYINT NOT NULL DEFAULT 1,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  priority INT NOT NULL DEFAULT 100,
  source VARCHAR(20) NOT NULL DEFAULT 'custom',
  version VARCHAR(50) NOT NULL DEFAULT '1',
  description VARCHAR(255) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id), KEY idx_policy_enabled_priority (enabled, priority), KEY idx_policy_source (source)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='自定义与导入防护策略'`},
	{"jyj_device_events", `CREATE TABLE IF NOT EXISTS jyj_device_events (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  device_name VARCHAR(100) NOT NULL,
  vendor VARCHAR(50) NOT NULL,
  format VARCHAR(20) NOT NULL,
  source_ip VARCHAR(64) NOT NULL,
  event_type VARCHAR(100) NOT NULL,
  severity TINYINT NOT NULL DEFAULT 1,
  event_ip VARCHAR(64) NULL,
  message VARCHAR(500) NULL,
  raw_json MEDIUMTEXT NULL,
  action_taken VARCHAR(30) NOT NULL DEFAULT 'recorded',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id), KEY idx_device_created (created_at), KEY idx_device_event_ip (event_ip), KEY idx_device_vendor (vendor)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='安全设备归一化事件'`},
	{"jyj_sites", `CREATE TABLE IF NOT EXISTS jyj_sites (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(100) NOT NULL,
  host VARCHAR(255) NOT NULL,
  upstream VARCHAR(2048) NOT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  pass_host TINYINT(1) NOT NULL DEFAULT 1,
  tls_skip_verify TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id), UNIQUE KEY uk_site_host (host), KEY idx_site_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='防护站点与源站路由'`},
	{"jyj_config", `CREATE TABLE IF NOT EXISTS jyj_config (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  config_key VARCHAR(100) NOT NULL,
  config_value TEXT NULL,
  config_desc VARCHAR(255) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id), UNIQUE KEY uk_config_key (config_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='系统配置（键值）'`},
	{"jyj_ip_list", `CREATE TABLE IF NOT EXISTS jyj_ip_list (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  ip VARCHAR(64) NOT NULL COMMENT 'IP/CIDR/通配符',
  type TINYINT NOT NULL DEFAULT 2 COMMENT '1=白名单 2=黑名单 3=临时黑名单',
  reason VARCHAR(255) NULL,
  expire_time DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id), KEY idx_type (type), KEY idx_ip (ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='IP 黑白名单'`},
	{"jyj_attack_log", `CREATE TABLE IF NOT EXISTS jyj_attack_log (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  event_id VARCHAR(40) NULL COMMENT '客户端拦截事件编号',
  ip VARCHAR(64) NOT NULL,
  ip_location VARCHAR(255) NULL,
  host VARCHAR(255) NULL,
  uri VARCHAR(500) NULL,
  method VARCHAR(10) NULL,
  attack_type VARCHAR(50) NOT NULL,
  severity TINYINT NOT NULL DEFAULT 1 COMMENT '1=信息 2=低危 3=中危 4=高危 5=严重',
  attack_detail VARCHAR(500) NULL,
  request_packet MEDIUMTEXT NULL,
  attack_count INT NOT NULL DEFAULT 0,
  status TINYINT NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id), KEY idx_event_id (event_id), KEY idx_ip_created_at (ip, created_at),
  KEY idx_attack_type_created (attack_type, created_at),
  KEY idx_attack_severity_created (severity, created_at), KEY idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='攻击日志'`},
	{"jyj_attack_event_ref", `CREATE TABLE IF NOT EXISTS jyj_attack_event_ref (
  event_id VARCHAR(40) NOT NULL,
  attack_log_id BIGINT UNSIGNED NOT NULL,
  occurred_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (event_id), KEY idx_attack_log_id (attack_log_id), KEY idx_event_occurred_at (occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='攻击事件编号索引'`},
	{"jyj_access_log", `CREATE TABLE IF NOT EXISTS jyj_access_log (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  ip VARCHAR(64) NOT NULL,
  host VARCHAR(255) NULL,
  uri VARCHAR(500) NULL,
  method VARCHAR(10) NULL,
  user_agent TEXT NULL,
  referer TEXT NULL,
  status INT NOT NULL DEFAULT 200,
  response_time DECIMAL(10,3) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id), KEY idx_ip_created_at (ip, created_at), KEY idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='访问日志'`},
	{"jyj_file_check", `CREATE TABLE IF NOT EXISTS jyj_file_check (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  file_path VARCHAR(500) NOT NULL,
  hash VARCHAR(64) NOT NULL,
  last_check_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status TINYINT NOT NULL DEFAULT 1,
  PRIMARY KEY (id), KEY idx_file_path (file_path(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='文件校验'`},
	{"jyj_users", `CREATE TABLE IF NOT EXISTS jyj_users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(50) NOT NULL,
  password VARCHAR(255) NOT NULL,
  email VARCHAR(100) NULL,
  status TINYINT NOT NULL DEFAULT 1,
  must_change_password TINYINT(1) NOT NULL DEFAULT 1,
  last_login_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id), UNIQUE KEY uk_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户管理'`},
	{"jyj_url_rules", `CREATE TABLE IF NOT EXISTS jyj_url_rules (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  url_pattern VARCHAR(500) NOT NULL,
  action TINYINT NOT NULL DEFAULT 2,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='URL 过滤规则'`},
	{"jyj_verify_fail", `CREATE TABLE IF NOT EXISTS jyj_verify_fail (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  ip VARCHAR(64) NOT NULL,
  fail_count INT NOT NULL DEFAULT 0,
  last_fail_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id), UNIQUE KEY uk_ip (ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='验证失败次数'`},
	{"jyj_login_log", `CREATE TABLE IF NOT EXISTS jyj_login_log (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NOT NULL,
  login_ip VARCHAR(64) NOT NULL,
  login_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id), KEY idx_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='登录日志'`},
	{"default_config", `INSERT INTO jyj_config (config_key, config_value, config_desc) VALUES
  ('system_status', '1', '系统总开关'),
  ('cc_protection_status', '1', 'CC 防护开关'),
  ('cc_visit_count', '100', 'CC 触发次数'),
  ('cc_visit_time', '60', 'CC 触发时间窗口（秒）'),
  ('cc_blacklist_time', '3600', '临时黑名单时长（秒）'),
  ('cc_verify_fail_limit', '10', '验证失败次数上限'),
  ('cc_whitelist_time', '1800', '验证通过后白名单时长（秒）'),
  ('cc_verification_mode', '1', '验证模式 1-8'),
  ('xss_protection_status', '1', 'XSS 防护开关'),
  ('sql_protection_status', '1', 'SQL 注入防护开关'),
  ('path_traversal_protection_status', '1', '路径穿越防护开关'),
  ('ssrf_protection_status', '1', 'SSRF 防护开关'),
  ('xxe_protection_status', '1', 'XXE/XML 注入防护开关'),
  ('file_check_status', '0', '文件校验开关'),
  ('oversea_ip_status', '0', '海外 IP 拦截开关'),
  ('log_keep_days', '30', '日志保留天数'),
  ('error_output_format', 'json', '错误输出格式 json/html'),
  ('custom_error_page', '', '自定义错误页模板'),
	('security_contact', '网站安全管理员', '拦截页联系信息'),
	('api_enabled', '1', '设备联动 API 开关'),
	('alert_cpu_percent', '80', 'CPU 使用率告警阈值'),
	('alert_memory_percent', '85', '内存使用率告警阈值'),
	('alert_disk_percent', '85', '磁盘使用率告警阈值'),
	('alert_log_size_mb', '512', '日志目录大小告警阈值 MB'),
	('alert_request_rate', '600', '业务请求速率告警阈值 每分钟'),
	('device_auto_block_enabled', '0', '设备高危事件自动封禁开关'),
	('device_auto_block_severity', '8', '设备自动封禁最低严重度'),
	('device_auto_block_seconds', '3600', '设备自动封禁时长秒'),
	('policy_auto_update', '0', '策略包自动更新开关'),
	('policy_update_url', '', '策略包 HTTPS 更新地址'),
	('policy_update_interval_minutes', '360', '策略包更新间隔分钟'),
	('policy_update_public_key', '', '策略包 Ed25519 公钥 Base64URL'),
	('policy_last_version', '', '最近策略包版本'),
	('policy_last_update', '', '最近策略更新时间'),
	('policy_last_error', '', '最近策略更新错误'),
  ('api_key', '', '设备联动 API 密钥')
ON DUPLICATE KEY UPDATE config_key = VALUES(config_key)`},
}

// Migrate creates all business tables and inserts missing default settings.
// Existing configuration values and application data are preserved.
func Migrate(ctx context.Context, db *sql.DB) error {
	for _, m := range schemaMigrations {
		if _, err := db.ExecContext(ctx, m.sql); err != nil {
			return fmt.Errorf("执行迁移 %s 失败: %w", m.name, err)
		}
	}
	if _, err := ensureColumn(ctx, db, "jyj_users", "must_change_password",
		"ALTER TABLE jyj_users ADD COLUMN must_change_password TINYINT(1) NOT NULL DEFAULT 1 AFTER status"); err != nil {
		return err
	}
	if _, err := ensureColumn(ctx, db, "jyj_sites", "tls_skip_verify",
		"ALTER TABLE jyj_sites ADD COLUMN tls_skip_verify TINYINT(1) NOT NULL DEFAULT 0 AFTER pass_host"); err != nil {
		return err
	}
	severityAdded, err := ensureColumn(ctx, db, "jyj_attack_log", "severity",
		"ALTER TABLE jyj_attack_log ADD COLUMN severity TINYINT NOT NULL DEFAULT 1 COMMENT '1=信息 2=低危 3=中危 4=高危 5=严重' AFTER attack_type")
	if err != nil {
		return err
	}
	if _, err := ensureColumn(ctx, db, "jyj_attack_log", "request_packet",
		"ALTER TABLE jyj_attack_log ADD COLUMN request_packet MEDIUMTEXT NULL AFTER attack_detail"); err != nil {
		return err
	}
	if _, err := ensureColumn(ctx, db, "jyj_attack_log", "event_id",
		"ALTER TABLE jyj_attack_log ADD COLUMN event_id VARCHAR(40) NULL COMMENT '客户端拦截事件编号' AFTER id"); err != nil {
		return err
	}
	if severityAdded {
		_, err = db.ExecContext(ctx, `UPDATE jyj_attack_log SET severity = CASE
  WHEN attack_type IN ('SQL注入', '穿盾攻击') THEN 5
  WHEN attack_type IN ('XSS攻击', 'IP黑名单') THEN 4
  WHEN attack_type IN ('CC攻击') OR (attack_type = '自定义策略' AND status = 1) THEN 3
  WHEN attack_type IN ('海外IP拦截', '验证失败次数过多') THEN 2
  ELSE 1 END`)
		if err != nil {
			return fmt.Errorf("回填攻击事件严重度失败: %w", err)
		}
	}
	for _, index := range []struct {
		name, sql string
	}{
		{"idx_ip_created_at", "ALTER TABLE jyj_attack_log ADD INDEX idx_ip_created_at (ip, created_at)"},
		{"idx_event_id", "ALTER TABLE jyj_attack_log ADD INDEX idx_event_id (event_id)"},
		{"idx_attack_type_created", "ALTER TABLE jyj_attack_log ADD INDEX idx_attack_type_created (attack_type, created_at)"},
		{"idx_attack_severity_created", "ALTER TABLE jyj_attack_log ADD INDEX idx_attack_severity_created (severity, created_at)"},
	} {
		if err := ensureIndex(ctx, db, "jyj_attack_log", index.name, index.sql); err != nil {
			return err
		}
	}
	return nil
}

func ensureColumn(ctx context.Context, db *sql.DB, table, column, alterSQL string) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?`, table, column).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("检查字段 %s.%s 失败: %w", table, column, err)
	}
	if count > 0 {
		return false, nil
	}
	if _, err := db.ExecContext(ctx, alterSQL); err != nil {
		return false, fmt.Errorf("新增字段 %s.%s 失败: %w", table, column, err)
	}
	return true, nil
}

func ensureIndex(ctx context.Context, db *sql.DB, table, index, alterSQL string) error {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.STATISTICS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ?`, table, index).Scan(&count)
	if err != nil {
		return fmt.Errorf("检查索引 %s.%s 失败: %w", table, index, err)
	}
	if count > 0 {
		return nil
	}
	if _, err := db.ExecContext(ctx, alterSQL); err != nil {
		return fmt.Errorf("新增索引 %s.%s 失败: %w", table, index, err)
	}
	return nil
}
