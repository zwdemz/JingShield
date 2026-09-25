package operations

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type queuedEvent struct {
	ID       int64
	Event    Event
	Attempts int
	Lease    string
}

type persistence interface {
	load(context.Context, string, any) error
	save(context.Context, string, any) error
	enqueue(context.Context, Event, int) error
	claim(context.Context) (*queuedEvent, error)
	finish(context.Context, *queuedEvent, bool, bool, time.Duration) error
	retry(context.Context) error
	counts(context.Context) (int, int, error)
	audit(context.Context, string, int) error
	auditWhitelist(context.Context, string, int) error
}

type sqlPersistence struct{ db *sql.DB }

func (p *sqlPersistence) load(ctx context.Context, key string, output any) error {
	var value string
	err := p.db.QueryRowContext(ctx, `SELECT config_value FROM jyj_config WHERE config_key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(value), output)
}

// save atomically persists settings and a credential-free administrative audit.
func (p *sqlPersistence) save(ctx context.Context, key string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO jyj_config (config_key,config_value) VALUES (?,?) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)`, key, string(body)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO jyj_device_events (device_name,vendor,format,source_ip,event_type,severity,message,action_taken) VALUES ('JingShield','JingShield','json','local',?,1,'Operational settings updated','configured')`, key); err != nil {
		return err
	}
	return tx.Commit()
}

// enqueue serializes the count-and-insert across nodes on a dedicated row lock;
// full queues reject new exports while preserving the original local audit log.
func (p *sqlPersistence) enqueue(ctx context.Context, event Event, capacity int) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var lockValue string
	if err = tx.QueryRowContext(ctx, `SELECT config_value FROM jyj_config WHERE config_key='operations_outbox_lock' FOR UPDATE`).Scan(&lockValue); err != nil {
		return err
	}
	var existing int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM jyj_syslog_outbox WHERE event_id=?`, event.deliveryKey()).Scan(&existing); err != nil {
		return err
	}
	if existing > 0 {
		return tx.Commit()
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM jyj_syslog_outbox`).Scan(&count); err != nil {
		return err
	}
	if count >= capacity {
		return ErrQueueFull
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO jyj_syslog_outbox (event_id,event_json,next_attempt) VALUES (?,?,UTC_TIMESTAMP())`, event.deliveryKey(), string(body)); err != nil {
		return err
	}
	return tx.Commit()
}

// claim leases one row before network I/O. The lease survives process termination
// and expires in 30 seconds; claim transactions never contain network work.
// Invalid event JSON is retained as a failed row in a committed transaction so
// subsequent claims can proceed. Errors identify the row without its payload.
func (p *sqlPersistence) claim(ctx context.Context) (*queuedEvent, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	item := &queuedEvent{}
	var body string
	err = tx.QueryRowContext(ctx, `SELECT id,event_json,attempts FROM jyj_syslog_outbox WHERE failed=0 AND next_attempt<=UTC_TIMESTAMP() AND (lease_until IS NULL OR lease_until<UTC_TIMESTAMP()) ORDER BY id LIMIT 1 FOR UPDATE`).Scan(&item.ID, &body, &item.Attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(body), &item.Event); err != nil {
		result, quarantineErr := tx.ExecContext(ctx, `UPDATE jyj_syslog_outbox SET failed=1,lease_until=NULL,lease_token='' WHERE id=?`, item.ID)
		if quarantineErr != nil {
			return nil, fmt.Errorf("quarantine invalid syslog outbox row %d: %w", item.ID, quarantineErr)
		}
		affected, quarantineErr := result.RowsAffected()
		if quarantineErr != nil {
			return nil, fmt.Errorf("check invalid syslog outbox row %d: %w", item.ID, quarantineErr)
		}
		if affected != 1 {
			return nil, fmt.Errorf("invalid syslog outbox row %d was not quarantined", item.ID)
		}
		if quarantineErr = tx.Commit(); quarantineErr != nil {
			return nil, fmt.Errorf("commit invalid syslog outbox row %d: %w", item.ID, quarantineErr)
		}
		return nil, fmt.Errorf("syslog outbox row %d contains invalid event JSON; marked failed", item.ID)
	}
	token := make([]byte, 16)
	if _, err = rand.Read(token); err != nil {
		return nil, err
	}
	item.Lease = hex.EncodeToString(token)
	if _, err = tx.ExecContext(ctx, `UPDATE jyj_syslog_outbox SET lease_token=?,lease_until=DATE_ADD(UTC_TIMESTAMP(),INTERVAL 30 SECOND) WHERE id=?`, item.Lease, item.ID); err != nil {
		return nil, err
	}
	return item, tx.Commit()
}

func (p *sqlPersistence) finish(ctx context.Context, item *queuedEvent, success, failed bool, delay time.Duration) error {
	var result sql.Result
	var err error
	if success {
		result, err = p.db.ExecContext(ctx, `DELETE FROM jyj_syslog_outbox WHERE id=? AND lease_token=?`, item.ID, item.Lease)
	} else {
		result, err = p.db.ExecContext(ctx, `UPDATE jyj_syslog_outbox SET attempts=attempts+1,failed=?,next_attempt=DATE_ADD(UTC_TIMESTAMP(),INTERVAL ? SECOND),lease_until=NULL,lease_token='' WHERE id=? AND lease_token=?`, failed, int(delay.Seconds()), item.ID, item.Lease)
	}
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err == nil && affected != 1 {
		return errors.New("delivery lease was lost")
	}
	return err
}

func (p *sqlPersistence) retry(ctx context.Context) error {
	_, err := p.db.ExecContext(ctx, `UPDATE jyj_syslog_outbox SET failed=0,attempts=0,next_attempt=UTC_TIMESTAMP(),lease_until=NULL,lease_token='' WHERE failed=1`)
	return err
}

func (p *sqlPersistence) counts(ctx context.Context) (int, int, error) {
	var queued, failed int
	err := p.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(failed=0),0),COALESCE(SUM(failed=1),0) FROM jyj_syslog_outbox`).Scan(&queued, &failed)
	return queued, failed, err
}

func (p *sqlPersistence) audit(ctx context.Context, outcome string, count int) error {
	_, err := p.db.ExecContext(ctx, `INSERT INTO jyj_device_events (device_name,vendor,format,source_ip,event_type,severity,message,action_taken) VALUES ('JingShield','JingShield','json','local','outbound_block_batch',5,?,?)`, fmt.Sprintf("requested_ips=%d", count), outcome)
	return err
}

// auditWhitelist records intent and outcome without exporting rule contents.
func (p *sqlPersistence) auditWhitelist(ctx context.Context, outcome string, count int) error {
	_, err := p.db.ExecContext(ctx, `INSERT INTO jyj_device_events (device_name,vendor,format,source_ip,event_type,severity,message,action_taken) VALUES ('JingShield','JingShield','json','local','outbound_whitelist_sync',1,?,?)`, fmt.Sprintf("rules=%d", count), outcome)
	return err
}
