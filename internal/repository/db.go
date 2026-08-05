package repository

// 数据库连接管理
// 提供 *sql.DB 连接池，供各 repository 复用

import (
	"database/sql"
	"fmt"
	"regexp"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"jingshield/internal/config"
)

var sqlIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// EnsureDatabase creates the configured database when it does not yet exist.
// Database and charset identifiers are strictly validated before interpolation.
func EnsureDatabase(cfg config.DatabaseConfig) error {
	if !sqlIdentifierPattern.MatchString(cfg.Name) {
		return fmt.Errorf("非法数据库名: %q", cfg.Name)
	}
	if !sqlIdentifierPattern.MatchString(cfg.Charset) {
		return fmt.Errorf("非法数据库字符集: %q", cfg.Charset)
	}
	// Prefer the least-privilege path. A normal runtime account commonly has
	// privileges on the application schema but no global CREATE DATABASE grant.
	// If the configured schema is already reachable there is nothing to create.
	existing, err := sql.Open("mysql", fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=true&loc=Local",
		cfg.User, cfg.Pass, cfg.Host, cfg.Port, cfg.Name, cfg.Charset,
	))
	if err == nil {
		if pingErr := existing.Ping(); pingErr == nil {
			existing.Close()
			return nil
		}
		existing.Close()
	}

	db, err := sql.Open("mysql", fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/?charset=%s&parseTime=true&loc=Local",
		cfg.User, cfg.Pass, cfg.Host, cfg.Port, cfg.Charset,
	))
	if err != nil {
		return fmt.Errorf("打开 MySQL 管理连接失败: %w", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return fmt.Errorf("MySQL 连通性校验失败: %w", err)
	}
	query := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` DEFAULT CHARACTER SET %s", cfg.Name, cfg.Charset)
	if _, err := db.Exec(query); err != nil {
		return fmt.Errorf("创建数据库失败: %w", err)
	}
	return nil
}

// NewDB 创建并初始化 MySQL 连接池
func NewDB(cfg config.DatabaseConfig) (*sql.DB, error) {
	db, err := sql.Open("mysql", fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=true&loc=Local",
		cfg.User, cfg.Pass, cfg.Host, cfg.Port, cfg.Name, cfg.Charset,
	))
	if err != nil {
		return nil, fmt.Errorf("打开数据库连接失败: %w", err)
	}

	// 连接池参数
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetime) * time.Second)

	// 连通性校验
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("数据库连通性校验失败: %w", err)
	}

	return db, nil
}
