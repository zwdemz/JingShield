package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"regexp"
)

var (
	ErrAlreadyInitialized = errors.New("系统已经初始化：jyj_users 中已存在管理员")
	usernamePattern       = regexp.MustCompile(`^[A-Za-z0-9_.-]{3,50}$`)
)

type InitialCredentials struct {
	Username string
	Password string
	APIKey   string
}

// Initialize creates the first administrator and API key in one transaction.
// It never changes or replaces an existing account.
func Initialize(ctx context.Context, db *sql.DB, username, email string) (*InitialCredentials, error) {
	if !usernamePattern.MatchString(username) {
		return nil, errors.New("管理员用户名只能包含字母、数字、点、下划线和短横线，长度 3-50")
	}
	if len(email) > 100 {
		return nil, errors.New("管理员邮箱长度不能超过 100")
	}

	var users int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM jyj_users").Scan(&users); err != nil {
		return nil, fmt.Errorf("检查管理员状态失败: %w", err)
	}
	if users > 0 {
		return nil, ErrAlreadyInitialized
	}

	password, err := randomPassword(20)
	if err != nil {
		return nil, fmt.Errorf("生成管理员密码失败: %w", err)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	apiKeyBytes := make([]byte, 32)
	if _, err := rand.Read(apiKeyBytes); err != nil {
		return nil, fmt.Errorf("生成 API Key 失败: %w", err)
	}
	apiKey := base64.RawURLEncoding.EncodeToString(apiKeyBytes)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("开始初始化事务失败: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		"INSERT INTO jyj_users (username, password, email, status) VALUES (?, ?, ?, 1)",
		username, hash, email); err != nil {
		return nil, fmt.Errorf("创建管理员失败: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		"UPDATE jyj_config SET config_value = ? WHERE config_key = 'api_key'", apiKey); err != nil {
		return nil, fmt.Errorf("写入 API Key 失败: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("提交初始化事务失败: %w", err)
	}
	return &InitialCredentials{Username: username, Password: password, APIKey: apiKey}, nil
}

func randomPassword(length int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%_-"
	if length < 12 {
		return "", errors.New("随机密码长度不能小于 12")
	}
	out := make([]byte, length)
	limit := big.NewInt(int64(len(alphabet)))
	for i := range out {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out), nil
}
