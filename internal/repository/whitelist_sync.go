package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"jingshield/internal/model"
	"jingshield/internal/pkg/iputil"
)

var whitelistSourceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

var ErrStaleWhitelist = errors.New("白名单版本早于已接收配置，请重新读取来源并发送最新快照")
var ErrWhitelistConflict = errors.New("同一白名单版本的内容不一致")

// WhitelistSyncResult acknowledges a durable source-owned snapshot. Manual
// whitelist entries and snapshots from other sources are never overwritten.
type WhitelistSyncResult struct {
	Source   string `json:"source"`
	Revision int64  `json:"revision"`
	Count    int    `json:"count"`
	Digest   string `json:"digest"`
}

// WhitelistSource exposes received rules to authenticated administrators.
type WhitelistSource struct {
	Source   string   `json:"source"`
	Revision int64    `json:"revision"`
	Rules    []string `json:"rules"`
}

// ValidWhitelistSource restricts peer ownership names to a stable safe token.
func ValidWhitelistSource(source string) bool { return whitelistSourceID.MatchString(source) }

// ManualWhitelistSnapshot reads only rules managed directly on this node, so
// two WAF peers do not endlessly re-export each other's received snapshots.
func (r *IPListRepo) ManualWhitelistSnapshot(ctx context.Context) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT ip FROM jyj_ip_list WHERE type=? ORDER BY id LIMIT 501`, model.IPTypeWhitelist)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := make([]string, 0)
	for rows.Next() {
		var rule string
		if err := rows.Scan(&rule); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return iputil.NormalizeWhitelistRules(rules)
}

// SyncWhitelist atomically replaces one authenticated peer's rules while
// retaining manually configured rules. Replayed versions are idempotent and
// old versions cannot undo a newer accepted snapshot.
func (r *IPListRepo) SyncWhitelist(ctx context.Context, source string, revision int64, input []string) (*WhitelistSyncResult, error) {
	if !ValidWhitelistSource(source) || revision <= 0 {
		return nil, errors.New("白名单来源或版本非法")
	}
	rules, err := iputil.NormalizeWhitelistRules(input)
	if err != nil {
		return nil, err
	}
	digestValue := sha256.Sum256([]byte(strings.Join(rules, "\n")))
	digest := hex.EncodeToString(digestValue[:])
	result := &WhitelistSyncResult{Source: source, Revision: revision, Count: len(rules), Digest: digest}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var previousRevision int64
	var previousDigest string
	err = tx.QueryRowContext(ctx, `SELECT revision,digest FROM jyj_synced_whitelist_state WHERE source_id=? FOR UPDATE`, source).Scan(&previousRevision, &previousDigest)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		if revision < previousRevision {
			return nil, ErrStaleWhitelist
		}
		if revision == previousRevision {
			if digest != previousDigest {
				return nil, ErrWhitelistConflict
			}
			return result, tx.Commit()
		}
	} else {
		var sources int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM jyj_synced_whitelist_state`).Scan(&sources); err != nil {
			return nil, err
		}
		if sources >= 16 {
			return nil, errors.New("白名单来源数量已达上限")
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM jyj_synced_whitelist WHERE source_id=?`, source); err != nil {
		return nil, err
	}
	for _, rule := range rules {
		if _, err = tx.ExecContext(ctx, `INSERT INTO jyj_synced_whitelist (source_id,rule) VALUES (?,?)`, source, rule); err != nil {
			return nil, err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO jyj_synced_whitelist_state (source_id,revision,digest) VALUES (?,?,?) ON DUPLICATE KEY UPDATE revision=VALUES(revision),digest=VALUES(digest)`, source, revision, digest); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO jyj_device_events (device_name,vendor,format,source_ip,event_type,severity,message,action_taken) VALUES ('JingShield','JingShield','json','local','whitelist_sync',1,?,'configured')`, source); err != nil {
		return nil, err
	}
	return result, tx.Commit()
}

// ReceivedWhitelist returns each source's accepted snapshot for admin review.
func (r *IPListRepo) ReceivedWhitelist(ctx context.Context) ([]WhitelistSource, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT source_id,revision FROM jyj_synced_whitelist_state ORDER BY source_id LIMIT 16`)
	if err != nil {
		return nil, err
	}
	sources := make([]WhitelistSource, 0)
	for rows.Next() {
		var source WhitelistSource
		if err := rows.Scan(&source.Source, &source.Revision); err != nil {
			rows.Close()
			return nil, err
		}
		source.Rules = []string{}
		sources = append(sources, source)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for index := range sources {
		entries, err := r.db.QueryContext(ctx, `SELECT rule FROM jyj_synced_whitelist WHERE source_id=? ORDER BY rule LIMIT 500`, sources[index].Source)
		if err != nil {
			return nil, err
		}
		for entries.Next() {
			var rule string
			if err := entries.Scan(&rule); err != nil {
				entries.Close()
				return nil, err
			}
			sources[index].Rules = append(sources[index].Rules, rule)
		}
		err = entries.Err()
		entries.Close()
		if err != nil {
			return nil, err
		}
	}
	return sources, nil
}
