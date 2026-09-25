package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// AttackIPSummary describes stored daily/type aggregates, not individual packets.
// LastSeen comes from the event-reference index, falling back for legacy data.
type AttackIPSummary struct {
	IP              string            `json:"ip"`
	Records         int64             `json:"records"`
	AttackCount     int64             `json:"attack_count"`
	BlockedRecords  int64             `json:"blocked_records"`
	ObservedRecords int64             `json:"observed_records"`
	MaxSeverity     int               `json:"max_severity"`
	FirstSeen       *time.Time        `json:"first_seen"`
	LastSeen        *time.Time        `json:"last_seen"`
	AttackTypes     []AttackTypeCount `json:"attack_types"`
	Hosts           []AttackHostCount `json:"hosts"`
	ListStatus      string            `json:"list_status"`
}

// AttackTypeCount contains one grouped detector count.
type AttackTypeCount struct {
	AttackType string `json:"attack_type"`
	Count      int64  `json:"count"`
}

// AttackHostCount contains one grouped host count; host is last recorded per bucket.
type AttackHostCount struct {
	Host  string `json:"host"`
	Count int64  `json:"count"`
}

// IPSummary returns a bounded indexed view for one exact IP. Database errors
// propagate to the API; no per-IP history is silently reported as empty.
func (r *AttackLogRepo) IPSummary(ctx context.Context, filter AttackLogFilter) (*AttackIPSummary, error) {
	if filter.IP == "" {
		return nil, errors.New("IP summary requires exact IP")
	}
	where, args := buildAttackLogWhere(filter)
	result := &AttackIPSummary{IP: filter.IP, AttackTypes: []AttackTypeCount{}, Hosts: []AttackHostCount{}, ListStatus: "none"}
	var first, last sql.NullTime
	query := `SELECT COUNT(*), COALESCE(SUM(attack_count),0), COALESCE(SUM(status=1),0), COALESCE(SUM(status=2),0), COALESCE(MAX(severity),0), MIN(created_at), MAX(COALESCE((SELECT MAX(occurred_at) FROM jyj_attack_event_ref WHERE attack_log_id=jyj_attack_log.id),created_at)) FROM jyj_attack_log` + where
	if err := r.db.QueryRowContext(ctx, query, args...).Scan(&result.Records, &result.AttackCount, &result.BlockedRecords, &result.ObservedRecords, &result.MaxSeverity, &first, &last); err != nil {
		return nil, err
	}
	if first.Valid {
		result.FirstSeen = &first.Time
	}
	if last.Valid {
		result.LastSeen = &last.Time
	}
	rows, err := r.db.QueryContext(ctx, "SELECT attack_type, SUM(attack_count) FROM jyj_attack_log"+where+" GROUP BY attack_type ORDER BY SUM(attack_count) DESC, attack_type LIMIT 50", args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var count AttackTypeCount
		if err := rows.Scan(&count.AttackType, &count.Count); err != nil {
			rows.Close()
			return nil, err
		}
		result.AttackTypes = append(result.AttackTypes, count)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = r.db.QueryContext(ctx, "SELECT COALESCE(host,''), SUM(attack_count) FROM jyj_attack_log"+where+" GROUP BY host ORDER BY SUM(attack_count) DESC, host LIMIT 20", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var count AttackHostCount
		if err := rows.Scan(&count.Host, &count.Count); err != nil {
			return nil, err
		}
		result.Hosts = append(result.Hosts, count)
	}
	return result, rows.Err()
}
