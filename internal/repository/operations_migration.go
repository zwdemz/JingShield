package repository

import (
	"context"
	"database/sql"
)

// MigrateOperations creates the bounded persistent delivery queue. It does not
// remove or replay existing events; failure is returned to the migration caller.
func MigrateOperations(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS jyj_syslog_outbox (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
 event_id VARCHAR(64) NOT NULL,
 event_json TEXT NOT NULL,
 attempts INT NOT NULL DEFAULT 0,
 next_attempt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 lease_token VARCHAR(64) NOT NULL DEFAULT '',
 lease_until DATETIME NULL,
 failed TINYINT(1) NOT NULL DEFAULT 0,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(id), UNIQUE KEY idx_syslog_event(event_id),
 KEY idx_syslog_pending(failed,next_attempt,lease_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Bounded sanitized syslog delivery outbox'`)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT IGNORE INTO jyj_config (config_key,config_value) VALUES ('operations_outbox_lock','1')`)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS jyj_synced_whitelist_state (
 source_id VARCHAR(64) NOT NULL PRIMARY KEY,
 revision BIGINT NOT NULL,
 digest CHAR(64) NOT NULL,
 updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Peer-owned whitelist snapshot version'`)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS jyj_synced_whitelist (
 source_id VARCHAR(64) NOT NULL,
 rule VARCHAR(64) NOT NULL,
 PRIMARY KEY (source_id,rule),
 KEY idx_synced_whitelist_rule(rule)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Peer-owned whitelist rules'`)
	return err
}
