package operations

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"jingshield/tests/testdb"
)

const quarantineStatement = "SET failed=1,lease_until=NULL,lease_token='' WHERE id=?"

func corruptClaimRow(body string) testdb.Step {
	return testdb.Step{
		Kind: "query", Contains: "WHERE failed=0 AND next_attempt<=UTC_TIMESTAMP()",
		Columns: []string{"id", "event_json", "attempts"},
		Values:  [][]driver.Value{{int64(4), body, int64(2)}},
	}
}

// TestSQLClaimCorruptEventCommitsFailureAndUnblocksNext verifies that malformed
// payloads remain recoverable, release any old lease, and never claim to deliver.
func TestSQLClaimCorruptEventCommitsFailureAndUnblocksNext(t *testing.T) {
	for name, body := range map[string]string{
		"syntax":       `{"private_payload":"do-not-log",`,
		"field_type":   `{"source_ip":123}`,
		"invalid_time": `{"occurred_at":"do-not-log"}`,
	} {
		t.Run(name, func(t *testing.T) {
			event := Event{ID: "healthy-event", IP: "192.0.2.1", Time: time.Now().UTC()}
			healthyBody, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			store := &sqlPersistence{db: testdb.Open(t,
				testdb.Step{Kind: "begin"},
				corruptClaimRow(body),
				testdb.Step{Kind: "exec", Contains: quarantineStatement, Check: func(args []driver.NamedValue) error {
					if len(args) != 1 || args[0].Value != int64(4) {
						return fmt.Errorf("quarantine targets the wrong row: %v", args)
					}
					return nil
				}},
				testdb.Step{Kind: "commit"},
				testdb.Step{Kind: "begin"},
				testdb.Step{Kind: "query", Contains: "WHERE failed=0", Columns: []string{"id", "event_json", "attempts"}, Values: [][]driver.Value{{int64(5), string(healthyBody), int64(3)}}},
				testdb.Step{Kind: "exec", Contains: "INTERVAL 30 SECOND", Check: func(args []driver.NamedValue) error {
					if len(args) != 2 || args[1].Value != int64(5) {
						return fmt.Errorf("healthy lease targets the wrong row: %v", args)
					}
					return nil
				}},
				testdb.Step{Kind: "commit"},
			)}
			item, err := store.claim(context.Background())
			if item != nil || err == nil || !strings.Contains(err.Error(), "row 4") || !strings.Contains(err.Error(), "marked failed") {
				t.Fatalf("corrupt row did not produce an observable failure: item=%#v err=%v", item, err)
			}
			if strings.Contains(err.Error(), body) || strings.Contains(err.Error(), "do-not-log") {
				t.Fatalf("claim error leaked event payload: %v", err)
			}
			item, err = store.claim(context.Background())
			if err != nil || item == nil || item.ID != 5 || item.Event.ID != event.ID || item.Attempts != 3 || len(item.Lease) != 32 {
				t.Fatalf("healthy event no longer claimable with its original retry count: item=%#v err=%v", item, err)
			}
		})
	}
}

// TestSQLClaimCorruptEventPersistenceFailure verifies that failed quarantine
// writes or commits remain errors instead of claiming that the row was handled.
func TestSQLClaimCorruptEventPersistenceFailure(t *testing.T) {
	for _, failAt := range []string{"exec", "commit"} {
		t.Run(failAt, func(t *testing.T) {
			failure := errors.New("mock persistence unavailable")
			steps := []testdb.Step{{Kind: "begin"}, corruptClaimRow(`broken`)}
			if failAt == "exec" {
				steps = append(steps, testdb.Step{Kind: "exec", Contains: quarantineStatement, Error: failure}, testdb.Step{Kind: "rollback"})
			} else {
				steps = append(steps, testdb.Step{Kind: "exec", Contains: quarantineStatement}, testdb.Step{Kind: "commit", Error: failure})
			}
			store := &sqlPersistence{db: testdb.Open(t, steps...)}
			item, err := store.claim(context.Background())
			if item != nil || !errors.Is(err, failure) || strings.Contains(err.Error(), "marked failed") {
				t.Fatalf("quarantine persistence failure was hidden: item=%#v err=%v", item, err)
			}
		})
	}
}

// TestSQLClaimCorruptEventMissingUpdateRollsBack verifies that an unexpected
// zero-row update cannot be reported as a successfully isolated corrupt event.
func TestSQLClaimCorruptEventMissingUpdateRollsBack(t *testing.T) {
	store, script := scriptedPersistence(t,
		sqlStep{fragment: "FOR UPDATE", rows: [][]driver.Value{{int64(4), `broken`, int64(2)}}},
		sqlStep{fragment: quarantineStatement, affected: 0},
	)
	item, err := store.claim(context.Background())
	if item != nil || err == nil || !strings.Contains(err.Error(), "not quarantined") || script.commits != 0 || script.rollbacks != 1 {
		t.Fatalf("missing quarantine update was accepted: item=%#v err=%v commits=%d rollbacks=%d", item, err, script.commits, script.rollbacks)
	}
}
