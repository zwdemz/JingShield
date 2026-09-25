package operations

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"jingshield/internal/model"
)

// Service owns an independently cancellable worker. Its persistent queue is
// shared across nodes; operational counters are process-local and labelled so.
type Service struct {
	store         persistence
	mu            sync.RWMutex
	changeMu      sync.Mutex
	syslog        SyslogConfig
	linkage       LinkageConfig
	syslogStatus  SyslogStatus
	linkageStatus LinkageStatus
	wake          chan struct{}
	cancel        context.CancelFunc
	done          chan struct{}
	send          func(context.Context, SyslogConfig, Event) error
	clientFactory func(LinkageConfig) peerClient
}

// New constructs disabled-by-default services; Start loads stored settings.
// A nil database is rejected by Start and by API callers, without network I/O.
func New(db *sql.DB) *Service {
	s := newService(&sqlPersistence{db: db})
	if db == nil {
		s.store = nil
	}
	return s
}

func newService(store persistence) *Service {
	return &Service{store: store,
		syslog:  SyslogConfig{Transport: "tls", Facility: 16, TimeoutSeconds: 3, MaxRetries: 3, QueueCapacity: 1000},
		linkage: LinkageConfig{Protocol: Protocol, DeviceType: "waf", TimeoutSeconds: 5},
		wake:    make(chan struct{}, 1), send: sendSyslog, clientFactory: newPeerClient,
	}
}

// Start validates persisted settings and starts exactly one worker. Queue leases
// permit recovery after restart; schema must have been migrated by the caller.
func (s *Service) Start(ctx context.Context) error {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	if s.store == nil {
		return ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return errors.New("operations worker already started")
	}
	if err := s.store.load(ctx, "operations_syslog_config", &s.syslog); err != nil {
		return err
	}
	if err := s.store.load(ctx, "operations_linkage_config", &s.linkage); err != nil {
		return err
	}
	if err := s.syslog.Validate(); err != nil {
		return err
	}
	if err := s.linkage.Validate(); err != nil {
		return err
	}
	runContext, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	s.syslogStatus.Running = true
	go s.run(runContext)
	return nil
}

// Close cancels pending I/O and waits until context expires. Unconfirmed events
// stay durable and become eligible after their 30-second lease expires.
func (s *Service) Close(ctx context.Context) error {
	s.mu.RLock()
	cancel, done := s.cancel, s.done
	s.mu.RUnlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Syslog returns configuration and live backlog; database failures are returned
// rather than reporting an empty healthy queue.
func (s *Service) Syslog(ctx context.Context) (SyslogConfig, SyslogStatus, error) {
	s.mu.RLock()
	cfg, status := s.syslog, s.syslogStatus
	s.mu.RUnlock()
	status.QueueCapacity = cfg.QueueCapacity
	status.Running = status.Running && cfg.Enabled
	status.DeliverySemantics = "transport_only_at_least_once"
	status.CounterScope = "current_process"
	if s.store == nil {
		return cfg, status, ErrUnavailable
	}
	var err error
	status.Queued, status.Failed, err = s.store.counts(ctx)
	return cfg, status, err
}

// ConfigureSyslog validates and atomically saves all fields plus an audit event.
// Saving never tests the destination or discards unsent queue entries.
func (s *Service) ConfigureSyslog(ctx context.Context, cfg SyslogConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if s.store == nil {
		return ErrUnavailable
	}
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	if err := s.store.save(ctx, "operations_syslog_config", cfg); err != nil {
		return err
	}
	s.mu.Lock()
	s.syslog = cfg
	s.mu.Unlock()
	s.signal()
	return nil
}

// Enqueue publishes only allowlisted metadata after local audit persistence.
// It never blocks a request goroutine, and limits audit-worker DB time to 200 ms.
// Full/unavailable exports increment dropped_total; local attack logs remain.
func (s *Service) Enqueue(ctx context.Context, log *model.AttackLog) error {
	s.mu.RLock()
	cfg := s.syslog
	s.mu.RUnlock()
	if !cfg.Enabled || log == nil {
		return nil
	}
	if s.store == nil {
		return ErrUnavailable
	}
	address := net.ParseIP(strings.TrimSpace(log.IP))
	if address == nil {
		return errors.New("invalid event IP")
	}
	event := Event{ID: safeField(log.EventID, 64), IP: address.String(), AttackType: safeField(log.AttackType, 64), Severity: log.Severity, Action: "blocked", Time: log.CreatedAt}
	if log.Status == 2 {
		event.Action = "observed"
	}
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	if event.ID == "" {
		token := make([]byte, 16)
		if _, err := rand.Read(token); err != nil {
			return err
		}
		event.ID = hex.EncodeToString(token)
	}
	// The request ID stays usable for local audit lookup. A stable decision ID
	// prevents observation and later enforcement from suppressing each other.
	digest := sha256.Sum256([]byte(event.ID + "\x00" + event.AttackType + "\x00" + event.Action))
	event.DeliveryID = hex.EncodeToString(digest[:])
	queueContext, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	err := s.store.enqueue(queueContext, event, cfg.QueueCapacity)
	if err != nil {
		s.mu.Lock()
		s.syslogStatus.DroppedTotal++
		s.syslogStatus.LastError = "outbox_enqueue_failed"
		if errors.Is(err, ErrQueueFull) {
			s.syslogStatus.LastError = "outbox_full"
		}
		s.mu.Unlock()
		return err
	}
	s.signal()
	return nil
}

// Sync resumes exhausted events only when explicitly requested and wakes the
// worker. It does not claim that pending logs were received by a collector.
func (s *Service) Sync(ctx context.Context, retryFailed bool) error {
	s.mu.RLock()
	enabled := s.syslog.Enabled
	s.mu.RUnlock()
	if !enabled {
		return errors.New("syslog 已停用，请先启用")
	}
	if s.store == nil {
		return ErrUnavailable
	}
	if retryFailed {
		if err := s.store.retry(ctx); err != nil {
			return err
		}
	}
	s.signal()
	return nil
}

func (s *Service) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Service) run(ctx context.Context) {
	defer func() { s.mu.Lock(); s.syslogStatus.Running = false; s.mu.Unlock(); close(s.done) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	refresh := time.NewTicker(10 * time.Second)
	defer refresh.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-refresh.C:
			s.refreshSettings(ctx)
		case <-ticker.C:
		case <-s.wake:
		}
		// Batches prevent a continuously growing queue from starving cancellation.
		for index := 0; index < 64 && ctx.Err() == nil; index++ {
			if !s.processOne(ctx) {
				break
			}
		}
	}
}

func (s *Service) refreshSettings(ctx context.Context) {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	s.mu.RLock()
	syslog, linkage := s.syslog, s.linkage
	s.mu.RUnlock()
	readContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if s.store.load(readContext, "operations_syslog_config", &syslog) != nil || s.store.load(readContext, "operations_linkage_config", &linkage) != nil || syslog.Validate() != nil || linkage.Validate() != nil {
		s.setSyslogError("settings_refresh_failed")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syslog = syslog
	if s.linkage != linkage {
		s.linkage = linkage
		s.linkageStatus = LinkageStatus{}
	}
}

func (s *Service) processOne(ctx context.Context) bool {
	s.mu.RLock()
	cfg := s.syslog
	s.mu.RUnlock()
	if !cfg.Enabled {
		return false
	}
	claimContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	item, err := s.store.claim(claimContext)
	cancel()
	if err != nil {
		s.setSyslogError("outbox_read_failed")
		return false
	}
	if item == nil {
		return false
	}
	if item.Attempts > 0 {
		s.mu.Lock()
		s.syslogStatus.RetriedTotal++
		s.mu.Unlock()
	}
	sendContext, cancel := context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
	err = s.send(sendContext, cfg, item.Event)
	cancel()
	if ctx.Err() != nil {
		return false
	}
	exhausted := err != nil && item.Attempts >= cfg.MaxRetries
	delay := time.Duration(1<<min(item.Attempts, 5)) * time.Second
	finishContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	finishErr := s.store.finish(finishContext, item, err == nil, exhausted, delay)
	cancel()
	if finishErr != nil {
		s.setSyslogError("outbox_checkpoint_failed")
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.syslogStatus.SentTotal++
		s.syslogStatus.LastSuccess = time.Now().UTC().Format(time.RFC3339)
		s.syslogStatus.LastError = ""
	} else {
		s.syslogStatus.LastError = "syslog_transport_failed"
		if exhausted {
			s.syslogStatus.LastError = "syslog_retries_exhausted"
		}
	}
	return true
}

func (s *Service) setSyslogError(code string) {
	s.mu.Lock()
	s.syslogStatus.LastError = code
	s.mu.Unlock()
}

func safeField(value string, limit int) string {
	var result strings.Builder
	for _, character := range value {
		if character < 32 || character == 127 {
			continue
		}
		if result.Len()+len(string(character)) > limit {
			break
		}
		result.WriteRune(character)
	}
	return result.String()
}
