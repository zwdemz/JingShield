// Package testdb provides deterministic SQL contracts without a real database.
package testdb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// Step describes one expected database call; Values contain mock data only.
type Step struct {
	Kind     string
	Contains string
	Columns  []string
	Values   [][]driver.Value
	Error    error
	Check    func([]driver.NamedValue) error
}

type script struct {
	mu      sync.Mutex
	steps   []Step
	failure error
}
type connector struct{ script *script }
type connection struct{ script *script }
type transaction struct{ script *script }
type rows struct {
	columns  []string
	values   [][]driver.Value
	position int
}
type mockDriver struct{}

// Open constructs a scripted database and checks all expected calls at cleanup.
// Unexpected SQL fails immediately; no sockets or external database are used.
func Open(t *testing.T, steps ...Step) *sql.DB {
	t.Helper()
	state := &script{steps: steps}
	db := sql.OpenDB(connector{script: state})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		db.Close()
		state.mu.Lock()
		defer state.mu.Unlock()
		if state.failure != nil {
			t.Error(state.failure)
		}
		if len(state.steps) > 0 {
			t.Errorf("%d SQL steps not executed; next %s %s", len(state.steps), state.steps[0].Kind, state.steps[0].Contains)
		}
	})
	return db
}

func (s *script) next(kind, query string, args []driver.NamedValue) (Step, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.steps) == 0 {
		s.failure = fmt.Errorf("unexpected %s: %s", kind, query)
		return Step{}, s.failure
	}
	step := s.steps[0]
	s.steps = s.steps[1:]
	if step.Kind != kind || !strings.Contains(query, step.Contains) {
		s.failure = fmt.Errorf("SQL got %s %s; expected %s %s", kind, query, step.Kind, step.Contains)
		return Step{}, s.failure
	}
	if step.Check != nil {
		if err := step.Check(args); err != nil {
			s.failure = err
			return Step{}, err
		}
	}
	return step, step.Error
}
func (c connector) Connect(context.Context) (driver.Conn, error) {
	return &connection{script: c.script}, nil
}
func (c connector) Driver() driver.Driver           { return mockDriver{} }
func (mockDriver) Open(string) (driver.Conn, error) { return nil, fmt.Errorf("use connector") }
func (c *connection) Prepare(string) (driver.Stmt, error) {
	return nil, fmt.Errorf("prepared statements unsupported in SQL contract")
}
func (c *connection) Close() error { return nil }
func (c *connection) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *connection) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	_, err := c.script.next("begin", "", nil)
	return &transaction{script: c.script}, err
}
func (c *connection) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	_, err := c.script.next("exec", query, args)
	return driver.RowsAffected(1), err
}
func (c *connection) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	step, err := c.script.next("query", query, args)
	return &rows{columns: step.Columns, values: step.Values}, err
}
func (t *transaction) Commit() error   { _, err := t.script.next("commit", "", nil); return err }
func (t *transaction) Rollback() error { _, err := t.script.next("rollback", "", nil); return err }
func (r *rows) Columns() []string      { return r.columns }
func (r *rows) Close() error           { return nil }
func (r *rows) Next(destination []driver.Value) error {
	if r.position >= len(r.values) {
		return io.EOF
	}
	copy(destination, r.values[r.position])
	r.position++
	return nil
}
