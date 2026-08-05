package repository

// 系统配置数据访问层（后台管理用）
// 动态配置的运行时读取由 config.DynamicConfig 负责，本仓储负责带描述的列表与批量更新

import (
	"context"
	"database/sql"

	"jingshield/internal/model"
)

// ConfigRepo 系统配置仓储（后台管理）
type ConfigRepo struct {
	db *sql.DB
}

// NewConfigRepo 构造
func NewConfigRepo(db *sql.DB) *ConfigRepo {
	return &ConfigRepo{db: db}
}

// ListAll 查询全部配置（含描述），后台展示用
func (r *ConfigRepo) ListAll(ctx context.Context) ([]*model.Config, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT id, config_key, config_value, config_desc, created_at, updated_at FROM jyj_config ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*model.Config
	for rows.Next() {
		c := &model.Config{}
		if err := rows.Scan(&c.ID, &c.ConfigKey, &c.ConfigValue, &c.ConfigDesc, &c.CreatedAt, &c.UpdatedAt); err != nil {
			continue
		}
		list = append(list, c)
	}
	return list, nil
}

// Update 更新单条配置值
func (r *ConfigRepo) Update(ctx context.Context, key, value string) error {
	_, err := r.db.ExecContext(ctx,
		"INSERT INTO jyj_config (config_key, config_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE config_value = ?",
		key, value, value)
	return err
}
