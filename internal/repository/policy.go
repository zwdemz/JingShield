package repository

import (
	"context"
	"database/sql"
	"errors"

	"jingshield/internal/model"
)

var ErrPolicyNotFound = errors.New("策略不存在")

type PolicyRepo struct{ db *sql.DB }

func NewPolicyRepo(db *sql.DB) *PolicyRepo { return &PolicyRepo{db: db} }

const policyColumns = "id, name, category, target, pattern, action, enabled, priority, source, version, COALESCE(description, ''), created_at, updated_at"

func scanPolicy(scanner interface{ Scan(...any) error }) (*model.PolicyRule, error) {
	rule := &model.PolicyRule{}
	err := scanner.Scan(&rule.ID, &rule.Name, &rule.Category, &rule.Target, &rule.Pattern, &rule.Action, &rule.Enabled, &rule.Priority, &rule.Source, &rule.Version, &rule.Description, &rule.CreatedAt, &rule.UpdatedAt)
	return rule, err
}

func (r *PolicyRepo) List(ctx context.Context) ([]*model.PolicyRule, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+policyColumns+" FROM jyj_policy_rules ORDER BY priority, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := make([]*model.PolicyRule, 0)
	for rows.Next() {
		rule, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, rule)
	}
	return list, rows.Err()
}

func (r *PolicyRepo) ListEnabled(ctx context.Context) ([]*model.PolicyRule, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+policyColumns+" FROM jyj_policy_rules WHERE enabled = 1 ORDER BY priority, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := make([]*model.PolicyRule, 0)
	for rows.Next() {
		rule, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, rule)
	}
	return list, rows.Err()
}

func (r *PolicyRepo) Create(ctx context.Context, rule *model.PolicyRule) error {
	res, err := r.db.ExecContext(ctx, `INSERT INTO jyj_policy_rules
		(name, category, target, pattern, action, enabled, priority, source, version, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.Name, rule.Category, rule.Target, rule.Pattern, rule.Action, rule.Enabled, rule.Priority, rule.Source, rule.Version, rule.Description)
	if err != nil {
		return err
	}
	rule.ID, _ = res.LastInsertId()
	return nil
}

func (r *PolicyRepo) Update(ctx context.Context, rule *model.PolicyRule) error {
	res, err := r.db.ExecContext(ctx, `UPDATE jyj_policy_rules SET name=?, category=?, target=?, pattern=?, action=?, enabled=?, priority=?, version=?, description=? WHERE id=?`,
		rule.Name, rule.Category, rule.Target, rule.Pattern, rule.Action, rule.Enabled, rule.Priority, rule.Version, rule.Description, rule.ID)
	if err != nil {
		return err
	}
	return changedPolicy(res)
}

func (r *PolicyRepo) Delete(ctx context.Context, id int64) error {
	res, err := r.db.ExecContext(ctx, "DELETE FROM jyj_policy_rules WHERE id = ?", id)
	if err != nil {
		return err
	}
	return changedPolicy(res)
}

func changedPolicy(result sql.Result) error {
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrPolicyNotFound
	}
	return nil
}

// ReplaceSource atomically replaces one imported source while preserving custom rules.
func (r *PolicyRepo) ReplaceSource(ctx context.Context, source string, rules []*model.PolicyRule) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM jyj_policy_rules WHERE source = ?", source); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO jyj_policy_rules
		(name, category, target, pattern, action, enabled, priority, source, version, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, rule := range rules {
		if _, err := stmt.ExecContext(ctx, rule.Name, rule.Category, rule.Target, rule.Pattern, rule.Action, rule.Enabled, rule.Priority, source, rule.Version, rule.Description); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *PolicyRepo) CountBySource(ctx context.Context) (map[string]int64, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT source, COUNT(*) FROM jyj_policy_rules GROUP BY source")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]int64{}
	for rows.Next() {
		var source string
		var count int64
		if err := rows.Scan(&source, &count); err != nil {
			return nil, err
		}
		result[source] = count
	}
	return result, rows.Err()
}
