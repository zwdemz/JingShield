package repository

// IP 黑白名单数据访问层
// 对应 PHP checkWhitelistIP()/checkBlacklistIP()/addTempBlacklist() 及后台 ip_whitelist.php

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"jingshield/internal/model"
	"jingshield/internal/pkg/iputil"
)

// IPListRepo IP 名单仓储
type IPListRepo struct {
	db *sql.DB
}

// NewIPListRepo 构造
func NewIPListRepo(db *sql.DB) *IPListRepo {
	return &IPListRepo{db: db}
}

// IsWhitelisted 判断 IP 是否在白名单（type=1）
// 对应 PHP checkWhitelistIP()
func (r *IPListRepo) IsWhitelisted(ctx context.Context, ip string) (bool, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT ip FROM jyj_ip_list WHERE type = ?", model.IPTypeWhitelist)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var rule string
		if err := rows.Scan(&rule); err != nil {
			return false, err
		}
		if iputil.MatchIPRule(ip, rule) {
			return true, nil
		}
	}
	return false, rows.Err()
}

// IsBlacklisted 判断 IP 是否在黑名单（永久 type=2 或未过期的临时 type=3）
// 对应 PHP checkBlacklistIP()
func (r *IPListRepo) IsBlacklisted(ctx context.Context, ip string) (bool, error) {
	now := time.Now().Format("2006-01-02 15:04:05")
	rows, err := r.db.QueryContext(ctx,
		`SELECT ip FROM jyj_ip_list
		 WHERE type = ? OR (type = ? AND expire_time > ?)`,
		model.IPTypeBlacklist, model.IPTypeTempBlacklist, now)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var rule string
		if err := rows.Scan(&rule); err != nil {
			return false, err
		}
		if iputil.MatchIPRule(ip, rule) {
			return true, nil
		}
	}
	return false, rows.Err()
}

// AddTempBlacklist 将 IP 加入临时黑名单（已存在则续期）
// 对应 PHP addTempBlacklist()
func (r *IPListRepo) AddTempBlacklist(ctx context.Context, ip, reason string, expireSecs int) error {
	expireTime := time.Now().Add(time.Duration(expireSecs) * time.Second).Format("2006-01-02 15:04:05")

	// 先查是否已存在临时黑名单记录
	var id int64
	err := r.db.QueryRowContext(ctx,
		"SELECT id FROM jyj_ip_list WHERE ip = ? AND type = ?", ip, model.IPTypeTempBlacklist).Scan(&id)
	switch {
	case err == nil:
		// 已存在，续期
		_, err = r.db.ExecContext(ctx,
			"UPDATE jyj_ip_list SET expire_time = ?, reason = ? WHERE ip = ? AND type = ?",
			expireTime, reason, ip, model.IPTypeTempBlacklist)
	case err == sql.ErrNoRows:
		// 不存在，新增
		_, err = r.db.ExecContext(ctx,
			"INSERT INTO jyj_ip_list (ip, type, reason, expire_time) VALUES (?, ?, ?, ?)",
			ip, model.IPTypeTempBlacklist, reason, expireTime)
	}
	if err != nil {
		return fmt.Errorf("加入临时黑名单失败: %w", err)
	}
	return nil
}

// RemoveTempBlacklist 移除 IP 的临时黑名单记录（验证成功后调用）
// 对应 PHP verify.php verificationSuccess() 的 DELETE
func (r *IPListRepo) RemoveTempBlacklist(ctx context.Context, ip string) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM jyj_ip_list WHERE ip = ? AND type = ?", ip, model.IPTypeTempBlacklist)
	return err
}

// CleanExpired 删除已过期的临时黑名单与黑名单记录
// 对应 PHP api.php 的清理逻辑
func (r *IPListRepo) CleanExpired(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM jyj_ip_list
		 WHERE type IN (?, ?) AND expire_time IS NOT NULL AND expire_time < NOW()`,
		model.IPTypeBlacklist, model.IPTypeTempBlacklist)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ListByType 按类型分页查询名单（后台管理用）
// ipType: 0=全部 1=白名单 2=黑名单 3=临时黑名单
func (r *IPListRepo) ListByType(ctx context.Context, ipType int, ip string, page, size int) ([]*model.IPList, int64, error) {
	where := " WHERE 1=1"
	args := []interface{}{}
	if ipType > 0 {
		where += " AND type = ?"
		args = append(args, ipType)
	}
	if ip != "" {
		where += " AND ip = ?"
		args = append(args, ip)
	}

	var total int64
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM jyj_ip_list"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * size
	if offset < 0 {
		offset = 0
	}
	query := "SELECT id, ip, type, reason, expire_time, created_at FROM jyj_ip_list" + where + " ORDER BY id DESC LIMIT ? OFFSET ?"
	args = append(args, size, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var list []*model.IPList
	for rows.Next() {
		item := &model.IPList{}
		if err := rows.Scan(&item.ID, &item.IP, &item.Type, &item.Reason, &item.ExpireTime, &item.CreatedAt); err != nil {
			continue
		}
		list = append(list, item)
	}
	return list, total, nil
}

// Add 新增名单记录
func (r *IPListRepo) Add(ctx context.Context, ip string, ipType int, reason string, expireTime *time.Time) error {
	var expireVal interface{}
	if expireTime != nil {
		expireVal = expireTime.Format("2006-01-02 15:04:05")
	}
	_, err := r.db.ExecContext(ctx,
		"INSERT INTO jyj_ip_list (ip, type, reason, expire_time) VALUES (?, ?, ?, ?)",
		ip, ipType, reason, expireVal)
	return err
}

// Delete 按 ID 删除名单记录
func (r *IPListRepo) Delete(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM jyj_ip_list WHERE id = ?", id)
	return err
}

// DeleteByIP 删除指定 IP 的永久及临时黑名单，保留白名单记录。
func (r *IPListRepo) DeleteByIP(ctx context.Context, ip string) (int64, error) {
	res, err := r.db.ExecContext(ctx,
		"DELETE FROM jyj_ip_list WHERE ip = ? AND type IN (?, ?)", ip, model.IPTypeBlacklist, model.IPTypeTempBlacklist)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountByType 按类型统计数量（仪表盘统计）
func (r *IPListRepo) CountByType(ctx context.Context, ipType int) (int64, error) {
	var c int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM jyj_ip_list WHERE type = ?", ipType).Scan(&c)
	return c, err
}

// CountBlacklist 黑名单（含临时）总数
// 对应 PHP getStatistics() 的 blacklist_ips
func (r *IPListRepo) CountBlacklist(ctx context.Context) (int64, error) {
	var c int64
	err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM jyj_ip_list WHERE type IN (?, ?)", model.IPTypeBlacklist, model.IPTypeTempBlacklist).Scan(&c)
	return c, err
}
