package repository

// 访问日志数据访问层
// 对应 PHP CCProtection::logAccess() 及后台 getRecentAttacks 等

import (
	"context"
	"database/sql"
	"fmt"

	"jingshield/internal/model"
)

// AccessLogRepo 访问日志仓储
type AccessLogRepo struct {
	db *sql.DB
}

// NewAccessLogRepo 构造
func NewAccessLogRepo(db *sql.DB) *AccessLogRepo {
	return &AccessLogRepo{db: db}
}

// Insert 写入一条访问日志
// 对应 PHP logAccess() 的 INSERT
func (r *AccessLogRepo) Insert(ctx context.Context, log *model.AccessLog) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO jyj_access_log (ip, host, uri, method, user_agent, referer, status, response_time, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
		log.IP, log.Host, log.URI, log.Method, log.UserAgent, log.Referer, log.Status, log.ResponseTime)
	if err != nil {
		return fmt.Errorf("写入访问日志失败: %w", err)
	}
	return nil
}

// CountByIPSince 统计某 IP 在 since 之后（含）的访问次数
// 对应 PHP checkTCPAttack() 的 SELECT COUNT(*) ... WHERE ip=? AND created_at>?
func (r *AccessLogRepo) CountByIPSince(ctx context.Context, ip, since string) (int64, error) {
	var count int64
	err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM jyj_access_log WHERE ip = ? AND created_at > ?", ip, since).Scan(&count)
	return count, err
}

// CountDistinctURIByIPSince 统计某 IP 在窗口内访问的不同 URL 数
// 对应 PHP checkVariantCCAttack() 的 SELECT COUNT(DISTINCT uri) ...
func (r *AccessLogRepo) CountDistinctURIByIPSince(ctx context.Context, ip, since string) (int64, error) {
	var count int64
	err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(DISTINCT uri) FROM jyj_access_log WHERE ip = ? AND created_at > ?", ip, since).Scan(&count)
	return count, err
}

// RecentTimestampsByIP 取某 IP 最近 N 条访问时间戳（降序）
// 对应 PHP checkShieldBypassAttack() 的方差分析数据源
func (r *AccessLogRepo) RecentTimestampsByIP(ctx context.Context, ip string, limit int) ([]string, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT created_at FROM jyj_access_log WHERE ip = ? ORDER BY created_at DESC LIMIT ?", ip, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ts []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			continue
		}
		ts = append(ts, t)
	}
	return ts, nil
}

// List 分页查询访问日志
// 对应后台 access_log.php 的列表查询
func (r *AccessLogRepo) List(ctx context.Context, ip string, page, size int) ([]*model.AccessLog, int64, error) {
	var total int64
	countSQL := "SELECT COUNT(*) FROM jyj_access_log"
	args := []interface{}{}
	if ip != "" {
		countSQL += " WHERE ip = ?"
		args = append(args, ip)
	}
	if err := r.db.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * size
	if offset < 0 {
		offset = 0
	}
	querySQL := "SELECT id, ip, host, uri, method, user_agent, referer, status, response_time, created_at FROM jyj_access_log"
	args2 := []interface{}{}
	if ip != "" {
		querySQL += " WHERE ip = ?"
		args2 = append(args2, ip)
	}
	querySQL += " ORDER BY id DESC LIMIT ? OFFSET ?"
	args2 = append(args2, size, offset)

	rows, err := r.db.QueryContext(ctx, querySQL, args2...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []*model.AccessLog
	for rows.Next() {
		l := &model.AccessLog{}
		if err := rows.Scan(&l.ID, &l.IP, &l.Host, &l.URI, &l.Method, &l.UserAgent,
			&l.Referer, &l.Status, &l.ResponseTime, &l.CreatedAt); err != nil {
			continue
		}
		logs = append(logs, l)
	}
	return logs, total, nil
}

// TotalCount 总访问数（仪表盘统计）
// 对应 PHP getStatistics() 的 SELECT COUNT(*) FROM jyj_access_log
func (r *AccessLogRepo) TotalCount(ctx context.Context) (int64, error) {
	var c int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM jyj_access_log").Scan(&c)
	return c, err
}

// DistinctIPCount 不同 IP 数（仪表盘统计）
func (r *AccessLogRepo) DistinctIPCount(ctx context.Context) (int64, error) {
	var c int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(DISTINCT ip) FROM jyj_access_log").Scan(&c)
	return c, err
}

// TodayCount 返回数据库当前时区自然日内的访问数。
func (r *AccessLogRepo) TodayCount(ctx context.Context) (int64, error) {
	var c int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM jyj_access_log WHERE created_at >= CURDATE()").Scan(&c)
	return c, err
}

// TodayDistinctIPCount 返回数据库当前时区自然日内的独立来源 IP 数。
func (r *AccessLogRepo) TodayDistinctIPCount(ctx context.Context) (int64, error) {
	var c int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(DISTINCT ip) FROM jyj_access_log WHERE created_at >= CURDATE()").Scan(&c)
	return c, err
}

// CountLastMinute 返回最近一分钟已进入访问日志的业务请求数。
func (r *AccessLogRepo) CountLastMinute(ctx context.Context) (int64, error) {
	var c int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM jyj_access_log WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 MINUTE)").Scan(&c)
	return c, err
}

// DeleteBefore 删除指定时间之前的日志（日志清理）
func (r *AccessLogRepo) DeleteBefore(ctx context.Context, before string) (int64, error) {
	res, err := r.db.ExecContext(ctx, "DELETE FROM jyj_access_log WHERE created_at < ?", before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
