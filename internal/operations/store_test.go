package operations

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The scripted SQL driver verifies transaction/control-flow contracts without
// connecting to a developer or production database.
type sqlStep struct {
	fragment string
	rows     [][]driver.Value
	affected int64
	failure  error
}
type sqlScript struct {
	t                                    *testing.T
	steps                                []sqlStep
	position, begins, commits, rollbacks int
}
type scriptDriver struct{}
type scriptConnection struct{ script *sqlScript }
type scriptTransaction struct{ script *sqlScript }
type scriptRows struct {
	rows     [][]driver.Value
	position int
}

var scriptSequence atomic.Uint64
var scripts sync.Map

func init() { sql.Register("operations-scripted", scriptDriver{}) }
func (scriptDriver) Open(name string) (driver.Conn, error) {
	value, ok := scripts.Load(name)
	if !ok {
		return nil, errors.New("missing SQL script")
	}
	return &scriptConnection{script: value.(*sqlScript)}, nil
}
func (c *scriptConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements not expected")
}
func (c *scriptConnection) Close() error { return nil }
func (c *scriptConnection) Begin() (driver.Tx, error) {
	c.script.begins++
	return &scriptTransaction{c.script}, nil
}
func (c *scriptConnection) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.Begin()
}
func (t *scriptTransaction) Commit() error   { t.script.commits++; return nil }
func (t *scriptTransaction) Rollback() error { t.script.rollbacks++; return nil }
func (c *scriptConnection) next(query string) sqlStep {
	script := c.script
	if script.position >= len(script.steps) {
		script.t.Fatalf("unexpected SQL %s", query)
	}
	step := script.steps[script.position]
	script.position++
	if !strings.Contains(query, step.fragment) {
		script.t.Fatalf("SQL %q lacks %q", query, step.fragment)
	}
	return step
}
func (c *scriptConnection) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	step := c.next(query)
	return driver.RowsAffected(step.affected), step.failure
}
func (c *scriptConnection) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	step := c.next(query)
	return &scriptRows{rows: step.rows}, step.failure
}
func (r *scriptRows) Columns() []string {
	count := 1
	if len(r.rows) > 0 {
		count = len(r.rows[0])
	}
	columns := make([]string, count)
	for index := range columns {
		columns[index] = fmt.Sprintf("column%d", index)
	}
	return columns
}
func (r *scriptRows) Close() error { return nil }
func (r *scriptRows) Next(output []driver.Value) error {
	if r.position >= len(r.rows) {
		return io.EOF
	}
	copy(output, r.rows[r.position])
	r.position++
	return nil
}
func scriptedPersistence(t *testing.T, steps ...sqlStep) (*sqlPersistence, *sqlScript) {
	t.Helper()
	name := fmt.Sprint(scriptSequence.Add(1))
	script := &sqlScript{t: t, steps: steps}
	scripts.Store(name, script)
	db, err := sql.Open("operations-scripted", name)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		db.Close()
		scripts.Delete(name)
		if script.position != len(script.steps) {
			t.Errorf("consumed %d/%d SQL steps", script.position, len(script.steps))
		}
	})
	return &sqlPersistence{db: db}, script
}

func TestSQLSettingsSaveIsAtomicAndAudited(t *testing.T) {
	for _, failAudit := range []bool{false, true} {
		t.Run(fmt.Sprint(failAudit), func(t *testing.T) {
			auditStep := sqlStep{fragment: "INSERT INTO jyj_device_events", affected: 1}
			if failAudit {
				auditStep.failure = errors.New("audit unavailable")
			}
			store, script := scriptedPersistence(t, sqlStep{fragment: "INSERT INTO jyj_config", affected: 1}, auditStep)
			err := store.save(context.Background(), "operations_syslog_config", SyslogConfig{})
			if failAudit {
				if err == nil || script.commits != 0 || script.rollbacks != 1 {
					t.Fatal("failed audit did not rollback settings")
				}
			} else if err != nil || script.commits != 1 {
				t.Fatalf("transaction failed %v", err)
			}
		})
	}
}

func TestSQLSettingsLoad(t *testing.T) {
	store, _ := scriptedPersistence(t, sqlStep{fragment: "SELECT config_value", rows: [][]driver.Value{{`{"enabled":true}`}}}, sqlStep{fragment: "SELECT config_value"}, sqlStep{fragment: "SELECT config_value", rows: [][]driver.Value{{`invalid`}}})
	var cfg SyslogConfig
	if err := store.load(context.Background(), "key", &cfg); err != nil || !cfg.Enabled {
		t.Fatal("load", err)
	}
	if err := store.load(context.Background(), "missing", &cfg); err != nil {
		t.Fatal(err)
	}
	if store.load(context.Background(), "broken", &cfg) == nil {
		t.Fatal("invalid persisted JSON accepted")
	}
}

func TestSQLOutboxCapacityAndDedupAreTransactional(t *testing.T) {
	for _, mode := range []string{"insert", "duplicate", "full"} {
		t.Run(mode, func(t *testing.T) {
			existing, total := int64(0), int64(0)
			if mode == "duplicate" {
				existing = 1
			}
			if mode == "full" {
				total = 1
			}
			steps := []sqlStep{{fragment: "FOR UPDATE", rows: [][]driver.Value{{"1"}}}, {fragment: "WHERE event_id", rows: [][]driver.Value{{existing}}}}
			if mode != "duplicate" {
				steps = append(steps, sqlStep{fragment: "SELECT COUNT(*) FROM jyj_syslog_outbox", rows: [][]driver.Value{{total}}})
			}
			if mode == "insert" {
				steps = append(steps, sqlStep{fragment: "UTC_TIMESTAMP()", affected: 1})
			}
			store, script := scriptedPersistence(t, steps...)
			err := store.enqueue(context.Background(), Event{ID: "unique"}, 1)
			if mode == "full" {
				if !errors.Is(err, ErrQueueFull) || script.rollbacks != 1 {
					t.Fatal("capacity not enforced", err)
				}
			} else if err != nil || script.commits != 1 {
				t.Fatal("enqueue not committed", err)
			}
		})
	}
}

func TestSQLClaimLeaseRecoveryAndAcknowledgement(t *testing.T) {
	body, _ := json.Marshal(Event{ID: "claim-test", IP: "192.0.2.1", Time: time.Now()})
	store, script := scriptedPersistence(t,
		sqlStep{fragment: "FOR UPDATE", rows: [][]driver.Value{{int64(4), string(body), int64(2)}}},
		sqlStep{fragment: "INTERVAL 30 SECOND", affected: 1},
		sqlStep{fragment: "DELETE FROM jyj_syslog_outbox WHERE id=? AND lease_token=?", affected: 1},
		sqlStep{fragment: "FOR UPDATE"},
	)
	item, err := store.claim(context.Background())
	if err != nil || item.ID != 4 || item.Attempts != 2 || len(item.Lease) != 32 || script.commits != 1 {
		t.Fatalf("invalid lease %#v %v", item, err)
	}
	if err = store.finish(context.Background(), item, true, false, 0); err != nil {
		t.Fatal(err)
	}
	if item, err = store.claim(context.Background()); err != nil || item != nil {
		t.Fatal("empty queue", err)
	}
}

func TestSQLRetryCountsFailureAndLeaseLoss(t *testing.T) {
	store, _ := scriptedPersistence(t,
		sqlStep{fragment: "attempts=attempts+1", affected: 1},
		sqlStep{fragment: "attempts=attempts+1", affected: 0},
		sqlStep{fragment: "COALESCE(SUM(failed=0)", rows: [][]driver.Value{{int64(2), int64(1)}}},
		sqlStep{fragment: "WHERE failed=1", affected: 1},
		sqlStep{fragment: "outbound_block_batch", affected: 1},
	)
	item := &queuedEvent{ID: 1, Lease: "token"}
	if err := store.finish(context.Background(), item, false, true, time.Second); err != nil {
		t.Fatal(err)
	}
	if store.finish(context.Background(), item, false, false, time.Second) == nil {
		t.Fatal("lost lease accepted")
	}
	queued, failed, err := store.counts(context.Background())
	if err != nil || queued != 2 || failed != 1 {
		t.Fatal("bad persisted status")
	}
	if err = store.retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = store.audit(context.Background(), "confirmed", 2); err != nil {
		t.Fatal(err)
	}
}
