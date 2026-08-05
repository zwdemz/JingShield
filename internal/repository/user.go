package repository

// 用户与登录日志数据访问层
// 对应 PHP admin/login.php 登录校验、admin/user_settings.php 改密

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"jingshield/internal/model"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound   = errors.New("用户不存在")
	ErrLastActiveUser = errors.New("不能停用最后一个启用的管理员")
)

// UserRepo 用户仓储
type UserRepo struct {
	db *sql.DB
}

// NewUserRepo 构造
func NewUserRepo(db *sql.DB) *UserRepo {
	return &UserRepo{db: db}
}

// FindByUsername 按用户名查询用户（登录校验用）
// 对应 PHP login.php 的 SELECT * FROM jyj_users WHERE username=?
func (r *UserRepo) FindByUsername(ctx context.Context, username string) (*model.User, error) {
	u := &model.User{}
	err := r.db.QueryRowContext(ctx,
		"SELECT id, username, password, COALESCE(email, ''), status, must_change_password, last_login_at, created_at FROM jyj_users WHERE username = ?",
		username).Scan(&u.ID, &u.Username, &u.Password, &u.Email, &u.Status, &u.MustChangePassword, &u.LastLoginAt, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// FindByID 按主键查询用户，用于会话内改密校验。
func (r *UserRepo) FindByID(ctx context.Context, id int64) (*model.User, error) {
	u := &model.User{}
	err := r.db.QueryRowContext(ctx,
		"SELECT id, username, password, COALESCE(email, ''), status, must_change_password, last_login_at, created_at FROM jyj_users WHERE id = ?",
		id).Scan(&u.ID, &u.Username, &u.Password, &u.Email, &u.Status, &u.MustChangePassword, &u.LastLoginAt, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// List 返回全部管理员账号，不包含密码哈希。
func (r *UserRepo) List(ctx context.Context) ([]*model.User, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT id, username, '', COALESCE(email, ''), status, must_change_password, last_login_at, created_at FROM jyj_users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*model.User
	for rows.Next() {
		u := &model.User{}
		if err := rows.Scan(&u.ID, &u.Username, &u.Password, &u.Email, &u.Status, &u.MustChangePassword, &u.LastLoginAt, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// Create 创建管理员账号。调用方负责校验用户名、邮箱和明文密码。
func (r *UserRepo) Create(ctx context.Context, username, email, passwordHash string) (*model.User, error) {
	res, err := r.db.ExecContext(ctx,
		"INSERT INTO jyj_users (username, password, email, status, must_change_password) VALUES (?, ?, ?, 1, 1)",
		username, passwordHash, email)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return r.FindByID(ctx, id)
}

// SetStatus 启停账号。停用操作在事务中锁定用户表，避免并发停用最后一个管理员。
func (r *UserRepo) SetStatus(ctx context.Context, userID int64, status int) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current int
	if err := tx.QueryRowContext(ctx, "SELECT status FROM jyj_users WHERE id = ? FOR UPDATE", userID).Scan(&current); err != nil {
		if err == sql.ErrNoRows {
			return ErrUserNotFound
		}
		return err
	}
	if status == 0 && current == 1 {
		var active int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM jyj_users WHERE status = 1 FOR UPDATE").Scan(&active); err != nil {
			return err
		}
		if active <= 1 {
			return ErrLastActiveUser
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE jyj_users SET status = ? WHERE id = ?", status, userID); err != nil {
		return err
	}
	return tx.Commit()
}

// ResetPassword 由管理员设置临时密码，目标用户下次登录必须修改。
func (r *UserRepo) ResetPassword(ctx context.Context, userID int64, newHash string) error {
	res, err := r.db.ExecContext(ctx, "UPDATE jyj_users SET password = ?, must_change_password = 1 WHERE id = ?", newHash, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// VerifyPassword 校验明文密码与 bcrypt 哈希是否匹配
// 与 PHP password_verify() 兼容（同样的 bcrypt $2y$ 格式）
func VerifyPassword(plain, hash string) bool {
	// PHP 的 $2y$ 前缀与 Go 的 $2a$ 等价，需统一前缀以兼容
	if len(hash) > 3 && hash[:3] == "$2y" {
		hash = "$2a" + hash[3:]
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
	return err == nil
}

// HashPassword 生成 bcrypt 哈希（与 PHP password_hash 兼容，cost=10）
func HashPassword(plain string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("密码哈希失败: %w", err)
	}
	// 转为 PHP 兼容的 $2y$ 前缀
	hash := string(h)
	if len(hash) > 3 && hash[:3] == "$2a" {
		hash = "$2y" + hash[3:]
	}
	return hash, nil
}

// UpdatePassword 更新用户密码
// 对应 PHP user_settings.php 的改密逻辑
func (r *UserRepo) UpdatePassword(ctx context.Context, userID int64, newHash string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE jyj_users SET password = ?, must_change_password = 0 WHERE id = ?", newHash, userID)
	return err
}

// UpdateLastLogin 更新最后登录时间
func (r *UserRepo) UpdateLastLogin(ctx context.Context, userID int64) error {
	_, err := r.db.ExecContext(ctx, "UPDATE jyj_users SET last_login_at = NOW() WHERE id = ?", userID)
	return err
}

// LoginLogRepo 登录日志仓储
type LoginLogRepo struct {
	db *sql.DB
}

// NewLoginLogRepo 构造
func NewLoginLogRepo(db *sql.DB) *LoginLogRepo {
	return &LoginLogRepo{db: db}
}

// Insert 写入登录日志
// 对应 PHP login.php 的 INSERT INTO jyj_login_log
func (r *LoginLogRepo) Insert(ctx context.Context, userID int64, ip string) error {
	_, err := r.db.ExecContext(ctx,
		"INSERT INTO jyj_login_log (user_id, login_ip, login_time) VALUES (?, ?, ?)",
		userID, ip, time.Now().Format("2006-01-02 15:04:05"))
	return err
}

// List 分页查询登录日志
func (r *LoginLogRepo) List(ctx context.Context, page, size int) ([]*model.LoginLog, int64, error) {
	var total int64
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM jyj_login_log").Scan(&total); err != nil {
		return nil, 0, err
	}
	offset := (page - 1) * size
	if offset < 0 {
		offset = 0
	}
	rows, err := r.db.QueryContext(ctx,
		"SELECT id, user_id, login_ip, login_time FROM jyj_login_log ORDER BY id DESC LIMIT ? OFFSET ?", size, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []*model.LoginLog
	for rows.Next() {
		l := &model.LoginLog{}
		if err := rows.Scan(&l.ID, &l.UserID, &l.LoginIP, &l.LoginTime); err != nil {
			continue
		}
		logs = append(logs, l)
	}
	return logs, total, nil
}
