package repository

// 攻击日志数据访问层
// 对应 PHP CCProtection::logAttack() 的 UPSERT 逻辑及后台攻击日志查询

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"jingshield/internal/model"
)

// AttackLogRepo 攻击日志仓储
type AttackLogRepo struct {
	db *sql.DB
}

// NewAttackLogRepo 构造
func NewAttackLogRepo(db *sql.DB) *AttackLogRepo {
	return &AttackLogRepo{db: db}
}

// UpsertAttack 记录一次攻击：当日已存在同 IP+类型则累加次数，否则新建
// 对应 PHP logAttack() 的 SELECT/UPDATE/INSERT 三段式逻辑
// 返回最新累计攻击次数
func (r *AttackLogRepo) UpsertAttack(ctx context.Context, log *model.AttackLog) (int, error) {
	if log.Status != 1 && log.Status != 2 {
		log.Status = 1
	}
	if log.Severity < model.AttackSeverityInfo || log.Severity > model.AttackSeverityCritical {
		log.Severity = model.AttackSeverityFor(log.AttackType, log.Status)
	}
	// 查询当日是否已存在同 IP 同类型记录
	var id int64
	var attackCount int
	err := r.db.QueryRowContext(ctx,
		`SELECT id, attack_count FROM jyj_attack_log
		 WHERE ip = ? AND attack_type = ? AND DATE(created_at) = CURDATE()`,
		log.IP, log.AttackType).Scan(&id, &attackCount)

	switch {
	case err == nil:
		// 已存在，累加次数
		attackCount++
		_, err = r.db.ExecContext(ctx,
			`UPDATE jyj_attack_log SET attack_count = ?, ip_location = ?, host = ?, uri = ?, method = ?,
			 attack_detail = ?, request_packet = ?, event_id = ?, severity = GREATEST(severity, ?), status = LEAST(status, ?) WHERE id = ?`,
			attackCount, log.IPLocation, log.Host, log.URI, log.Method, log.AttackDetail, log.RequestPacket, log.EventID, log.Severity, log.Status, id)
		if err != nil {
			return attackCount, fmt.Errorf("更新攻击次数失败: %w", err)
		}
		if err := r.storeEventReference(ctx, log.EventID, id); err != nil {
			return attackCount, err
		}
	case err == sql.ErrNoRows:
		// 不存在，新建
		attackCount = 1
		result, insertErr := r.db.ExecContext(ctx,
			`INSERT INTO jyj_attack_log (event_id, ip, ip_location, host, uri, method, attack_type, severity, attack_detail, request_packet, attack_count, status, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
			log.EventID, log.IP, log.IPLocation, log.Host, log.URI, log.Method,
			log.AttackType, log.Severity, log.AttackDetail, log.RequestPacket, attackCount, log.Status)
		if insertErr != nil {
			return attackCount, fmt.Errorf("写入攻击日志失败: %w", insertErr)
		}
		id, err = result.LastInsertId()
		if err != nil {
			return attackCount, fmt.Errorf("读取攻击日志 ID 失败: %w", err)
		}
		if err := r.storeEventReference(ctx, log.EventID, id); err != nil {
			return attackCount, err
		}
	default:
		return attackCount, fmt.Errorf("查询攻击日志失败: %w", err)
	}
	return attackCount, nil
}

func (r *AttackLogRepo) storeEventReference(ctx context.Context, eventID string, attackLogID int64) error {
	if eventID == "" {
		return nil
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO jyj_attack_event_ref (event_id, attack_log_id, occurred_at) VALUES (?, ?, NOW())
		 ON DUPLICATE KEY UPDATE attack_log_id = VALUES(attack_log_id), occurred_at = VALUES(occurred_at)`,
		eventID, attackLogID)
	if err != nil {
		return fmt.Errorf("写入攻击事件编号索引失败: %w", err)
	}
	return nil
}

type AttackLogFilter struct {
	EventID    string
	AttackType string
	IP         string
	Severity   int
	StartAt    *time.Time
	EndAt      *time.Time
}

func buildAttackLogWhere(filter AttackLogFilter) (string, []any) {
	where := " WHERE 1=1"
	args := []any{}
	if filter.EventID != "" {
		where += " AND id = (SELECT attack_log_id FROM jyj_attack_event_ref WHERE event_id = ? LIMIT 1)"
		args = append(args, filter.EventID)
	}
	if filter.AttackType != "" {
		where += " AND attack_type = ?"
		args = append(args, filter.AttackType)
	}
	if filter.IP != "" {
		where += " AND ip = ?"
		args = append(args, filter.IP)
	}
	if filter.Severity >= model.AttackSeverityInfo && filter.Severity <= model.AttackSeverityCritical {
		where += " AND severity = ?"
		args = append(args, filter.Severity)
	}
	if filter.StartAt != nil {
		where += " AND created_at >= ?"
		args = append(args, *filter.StartAt)
	}
	if filter.EndAt != nil {
		where += " AND created_at < ?"
		args = append(args, *filter.EndAt)
	}
	return where, args
}

// List performs indexed server-side pagination for attack events.
func (r *AttackLogRepo) List(ctx context.Context, filter AttackLogFilter, page, size int) ([]*model.AttackLog, int64, error) {
	where, args := buildAttackLogWhere(filter)

	var total int64
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM jyj_attack_log"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * size
	if offset < 0 {
		offset = 0
	}
	query := "SELECT id, COALESCE(event_id, ''), ip, ip_location, host, uri, method, attack_type, severity, attack_detail, COALESCE(request_packet, ''), attack_count, status, created_at FROM jyj_attack_log" +
		where + " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
	args = append(args, size, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []*model.AttackLog
	for rows.Next() {
		l := &model.AttackLog{}
		if err := rows.Scan(&l.ID, &l.EventID, &l.IP, &l.IPLocation, &l.Host, &l.URI, &l.Method,
			&l.AttackType, &l.Severity, &l.AttackDetail, &l.RequestPacket, &l.AttackCount, &l.Status, &l.CreatedAt); err != nil {
			return nil, 0, err
		}
		if filter.EventID != "" {
			// 精确编号查询应回显用户提交的历史编号，而不是聚合行上的最新编号。
			l.EventID = filter.EventID
		}
		logs = append(logs, l)
	}
	return logs, total, rows.Err()
}

// Stream walks every matching event in a stable order without buffering the
// full result set. It is used by CSV export for large datasets.
func (r *AttackLogRepo) Stream(ctx context.Context, filter AttackLogFilter, visit func(*model.AttackLog) error) error {
	where, args := buildAttackLogWhere(filter)
	query := "SELECT id, COALESCE(event_id, ''), ip, ip_location, host, uri, method, attack_type, severity, attack_detail, COALESCE(request_packet, ''), attack_count, status, created_at FROM jyj_attack_log" +
		where + " ORDER BY created_at DESC, id DESC"
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		log := &model.AttackLog{}
		if err := rows.Scan(&log.ID, &log.EventID, &log.IP, &log.IPLocation, &log.Host, &log.URI, &log.Method,
			&log.AttackType, &log.Severity, &log.AttackDetail, &log.RequestPacket, &log.AttackCount, &log.Status, &log.CreatedAt); err != nil {
			return err
		}
		if filter.EventID != "" {
			log.EventID = filter.EventID
		}
		if err := visit(log); err != nil {
			return err
		}
	}
	return rows.Err()
}

// SumAttackCount 攻击总次数（仪表盘统计）
// 对应 PHP getStatistics() 的 SELECT SUM(attack_count)
func (r *AttackLogRepo) SumAttackCount(ctx context.Context) (int64, error) {
	var c sql.NullInt64
	err := r.db.QueryRowContext(ctx, "SELECT SUM(attack_count) FROM jyj_attack_log").Scan(&c)
	if err != nil {
		return 0, err
	}
	if !c.Valid {
		return 0, nil
	}
	return c.Int64, nil
}

// TodaySumAttackCount 返回数据库当前时区自然日内的攻击总次数。
func (r *AttackLogRepo) TodaySumAttackCount(ctx context.Context) (int64, error) {
	var c sql.NullInt64
	err := r.db.QueryRowContext(ctx, "SELECT SUM(attack_count) FROM jyj_attack_log WHERE created_at >= CURDATE()").Scan(&c)
	if err != nil || !c.Valid {
		return 0, err
	}
	return c.Int64, nil
}

// TopAttackIPs 攻击次数 Top N 的 IP
// 对应 PHP getTopAttackIPs()
func (r *AttackLogRepo) TopAttackIPs(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT ip, SUM(attack_count) AS cnt FROM jyj_attack_log GROUP BY ip ORDER BY cnt DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var ip string
		var cnt int64
		if err := rows.Scan(&ip, &cnt); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{"ip": ip, "count": cnt})
	}
	return result, nil
}

// TodayTopAttackIPs 返回今日攻击次数最高的来源 IP。
func (r *AttackLogRepo) TodayTopAttackIPs(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT ip, SUM(attack_count) AS cnt FROM jyj_attack_log WHERE created_at >= CURDATE() GROUP BY ip ORDER BY cnt DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []map[string]interface{}
	for rows.Next() {
		var ip string
		var cnt int64
		if err := rows.Scan(&ip, &cnt); err != nil {
			return nil, err
		}
		result = append(result, map[string]interface{}{"ip": ip, "count": cnt})
	}
	return result, rows.Err()
}

// HourlyTrend 最近 24 小时每小时的攻击次数
// 对应 PHP getAttackTrend()
func (r *AttackLogRepo) HourlyTrend(ctx context.Context) ([]map[string]interface{}, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT DATE_FORMAT(created_at, '%H') AS h, SUM(attack_count) AS cnt
		 FROM jyj_attack_log
		 WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
		 GROUP BY h ORDER BY h`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var h string
		var cnt int64
		if err := rows.Scan(&h, &cnt); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{"hour": h, "count": cnt})
	}
	return result, nil
}

// TodayHourlyTrend 返回今日从 00 时起按小时聚合的攻击次数。
func (r *AttackLogRepo) TodayHourlyTrend(ctx context.Context) ([]map[string]interface{}, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT DATE_FORMAT(created_at, '%H') AS h, SUM(attack_count) AS cnt
		 FROM jyj_attack_log WHERE created_at >= CURDATE()
		 GROUP BY h ORDER BY h`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []map[string]interface{}
	for rows.Next() {
		var h string
		var cnt int64
		if err := rows.Scan(&h, &cnt); err != nil {
			return nil, err
		}
		result = append(result, map[string]interface{}{"hour": h, "count": cnt})
	}
	return result, rows.Err()
}

func (r *AttackLogRepo) TodayCountByType(ctx context.Context) (map[string]int64, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT attack_type, SUM(attack_count) FROM jyj_attack_log WHERE created_at >= CURDATE() GROUP BY attack_type")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]int64{}
	for rows.Next() {
		var attackType string
		var count int64
		if err := rows.Scan(&attackType, &count); err != nil {
			return nil, err
		}
		result[attackType] = count
	}
	return result, rows.Err()
}
