package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"jingshield/internal/model"
	"jingshield/internal/pkg/iputil"
	"sort"
	"strings"
	"time"
)

// BlockBatchResult differentiates submitted entries, unique addresses and
// whitelist skips. No partial success is returned after a transaction failure.
type BlockBatchResult struct {
	Requested        int      `json:"requested"`
	Unique           int      `json:"unique"`
	Blocked          int      `json:"blocked"`
	SkippedWhitelist int      `json:"skipped_whitelist"`
	SkippedIPs       []string `json:"skipped_ips"`
}

const blockAuditSchema = `CREATE TABLE IF NOT EXISTS jyj_ip_action_log (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 actor VARCHAR(100) NOT NULL, reason VARCHAR(255) NOT NULL,
 ips_json TEXT NOT NULL, requested INT NOT NULL, blocked INT NOT NULL,
 skipped_whitelist INT NOT NULL, expire_seconds INT NOT NULL,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 KEY idx_ip_action_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='批量 IP 处置审计'`

// BlockBatch updates up to 500 IPs and its audit record in one transaction.
// Whitelisted addresses (including CIDR/wildcard matches) are never changed.
// Existing permanent or longer temporary blocks are not shortened by retries.
func (r *IPListRepo) BlockBatch(ctx context.Context, input []string, reason string, expireSeconds int, actor string) (*BlockBatchResult, error) {
	ips, err := iputil.NormalizeBlockIPs(input)
	if err != nil {
		return nil, err
	}
	if !iputil.ValidBlockReason(reason) || expireSeconds < 0 || expireSeconds > 31536000 || len(actor) == 0 || len(actor) > 100 {
		return nil, errors.New("封禁原因、期限或操作者非法")
	}
	sort.Strings(ips)
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Lock the whitelist range for the transaction; a concurrent whitelist edit
	// must not be overwritten between validation and applying the block list.
	rows, err := tx.QueryContext(ctx, "SELECT ip FROM jyj_ip_list WHERE type = ? FOR UPDATE", model.IPTypeWhitelist)
	if err != nil {
		return nil, err
	}
	whitelist := []string{}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			rows.Close()
			return nil, err
		}
		whitelist = append(whitelist, value)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	peerRows, err := tx.QueryContext(ctx, "SELECT rule FROM jyj_synced_whitelist FOR UPDATE")
	if err != nil {
		return nil, err
	}
	for peerRows.Next() {
		var rule string
		if err := peerRows.Scan(&rule); err != nil {
			peerRows.Close()
			return nil, err
		}
		whitelist = append(whitelist, rule)
	}
	err = peerRows.Err()
	peerRows.Close()
	if err != nil {
		return nil, err
	}
	result := &BlockBatchResult{Requested: len(input), Unique: len(ips), SkippedIPs: []string{}}
	for _, ip := range ips {
		allowed := false
		for _, rule := range whitelist {
			if iputil.MatchIPRule(ip, rule) {
				allowed = true
				break
			}
		}
		if allowed {
			result.SkippedIPs = append(result.SkippedIPs, ip)
			result.SkippedWhitelist++
			continue
		}
		if err := blockIPInTransaction(ctx, tx, ip, strings.TrimSpace(reason), expireSeconds); err != nil {
			return nil, err
		}
		result.Blocked++
	}
	encoded, err := json.Marshal(ips)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO jyj_ip_action_log (actor, reason, ips_json, requested, blocked, skipped_whitelist, expire_seconds) VALUES (?, ?, ?, ?, ?, ?, ?)`, actor, strings.TrimSpace(reason), string(encoded), result.Requested, result.Blocked, result.SkippedWhitelist, expireSeconds); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// blockIPInTransaction locks existing rules and preserves the strongest expiry.
// Any statement error is returned to the caller so the whole batch rolls back.
func blockIPInTransaction(ctx context.Context, tx *sql.Tx, ip, reason string, seconds int) error {
	typ := model.IPTypeBlacklist
	var expires any
	if seconds > 0 {
		typ = model.IPTypeTempBlacklist
		expires = time.Now().Add(time.Duration(seconds) * time.Second)
	}
	rows, err := tx.QueryContext(ctx, "SELECT type, expire_time FROM jyj_ip_list WHERE ip = ? AND type IN (?, ?) FOR UPDATE", ip, model.IPTypeBlacklist, model.IPTypeTempBlacklist)
	if err != nil {
		return err
	}
	for rows.Next() {
		var existingType int
		var existingExpiry sql.NullTime
		if err := rows.Scan(&existingType, &existingExpiry); err != nil {
			rows.Close()
			return err
		}
		if existingType == model.IPTypeBlacklist {
			typ = model.IPTypeBlacklist
			expires = nil
		}
		if typ == model.IPTypeTempBlacklist && existingExpiry.Valid && existingExpiry.Time.After(expires.(time.Time)) {
			expires = existingExpiry.Time
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM jyj_ip_list WHERE ip = ? AND type IN (?, ?)", ip, model.IPTypeBlacklist, model.IPTypeTempBlacklist); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO jyj_ip_list (ip, type, reason, expire_time) VALUES (?, ?, ?, ?)", ip, typ, reason, expires)
	return err
}
