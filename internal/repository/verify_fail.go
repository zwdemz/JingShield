package repository

// 验证失败次数数据访问层
// 对应 PHP CCProtection::recordVerifyFail()/resetVerifyFail()/checkVerifyFailLimit()

import (
	"context"
	"database/sql"
)

// VerifyFailRepo 验证失败次数仓储
type VerifyFailRepo struct {
	db *sql.DB
}

// NewVerifyFailRepo 构造
func NewVerifyFailRepo(db *sql.DB) *VerifyFailRepo {
	return &VerifyFailRepo{db: db}
}

// RecordFail 记录一次验证失败：累加失败次数
// 对应 PHP recordVerifyFail() 的 INSERT ... ON DUPLICATE KEY UPDATE fail_count=fail_count+1
func (r *VerifyFailRepo) RecordFail(ctx context.Context, ip string) (int, error) {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO jyj_verify_fail (ip, fail_count, last_fail_time) VALUES (?, 1, NOW())
		 ON DUPLICATE KEY UPDATE fail_count = fail_count + 1, last_fail_time = NOW()`, ip)
	if err != nil {
		return 0, err
	}
	// 查询最新失败次数
	var count int
	err = r.db.QueryRowContext(ctx, "SELECT fail_count FROM jyj_verify_fail WHERE ip = ?", ip).Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}

// GetFailCount 查询某 IP 当前失败次数
// 对应 PHP checkVerifyFailLimit() 的查询
func (r *VerifyFailRepo) GetFailCount(ctx context.Context, ip string) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT fail_count FROM jyj_verify_fail WHERE ip = ?", ip).Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}

// Reset 清零某 IP 的验证失败次数
// 对应 PHP resetVerifyFail() / verify.php verificationSuccess() 的 DELETE
func (r *VerifyFailRepo) Reset(ctx context.Context, ip string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM jyj_verify_fail WHERE ip = ?", ip)
	return err
}
