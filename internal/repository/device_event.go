package repository

import (
	"context"
	"database/sql"

	"jingshield/internal/model"
)

type DeviceEventRepo struct{ db *sql.DB }

func NewDeviceEventRepo(db *sql.DB) *DeviceEventRepo { return &DeviceEventRepo{db: db} }

func (r *DeviceEventRepo) Insert(ctx context.Context, event *model.DeviceEvent) error {
	res, err := r.db.ExecContext(ctx, `INSERT INTO jyj_device_events
		(device_name, vendor, format, source_ip, event_type, severity, event_ip, message, raw_json, action_taken)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, event.DeviceName, event.Vendor, event.Format, event.SourceIP, event.EventType, event.Severity, event.EventIP, event.Message, event.RawJSON, event.ActionTaken)
	if err != nil {
		return err
	}
	event.ID, _ = res.LastInsertId()
	return nil
}

func (r *DeviceEventRepo) List(ctx context.Context, vendor string, page, size int) ([]*model.DeviceEvent, int64, error) {
	where, args := "", []any{}
	if vendor != "" {
		where = " WHERE vendor = ?"
		args = append(args, vendor)
	}
	var total int64
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM jyj_device_events"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	queryArgs := append(append([]any{}, args...), size, (page-1)*size)
	rows, err := r.db.QueryContext(ctx, `SELECT id, device_name, vendor, format, source_ip, event_type, severity,
		COALESCE(event_ip, ''), COALESCE(message, ''), '', action_taken, created_at FROM jyj_device_events`+where+" ORDER BY id DESC LIMIT ? OFFSET ?", queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	list := make([]*model.DeviceEvent, 0)
	for rows.Next() {
		e := &model.DeviceEvent{}
		if err := rows.Scan(&e.ID, &e.DeviceName, &e.Vendor, &e.Format, &e.SourceIP, &e.EventType, &e.Severity, &e.EventIP, &e.Message, &e.RawJSON, &e.ActionTaken, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		list = append(list, e)
	}
	return list, total, rows.Err()
}
