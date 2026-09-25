package protection

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"jingshield/internal/model"
	"jingshield/internal/pkg/logx"
	"jingshield/internal/repository"
)

const auditQueueSize = 2048

// auditWriter bounds pending database work so slow storage cannot create one goroutine per request.
type auditWriter struct {
	accessRepo *repository.AccessLogRepo
	attackRepo *repository.AttackLogRepo
	access     chan *model.AccessLog
	attack     chan *model.AttackLog
	dropped    atomic.Uint64
	failed     atomic.Uint64
	closeBy    atomic.Int64
	wg         sync.WaitGroup
}

func newAuditWriter(access *repository.AccessLogRepo, attack *repository.AttackLogRepo) *auditWriter {
	w := &auditWriter{accessRepo: access, attackRepo: attack, access: make(chan *model.AccessLog, auditQueueSize), attack: make(chan *model.AttackLog, auditQueueSize)}
	w.wg.Add(2)
	go w.writeAccess()
	go w.writeAttacks()
	return w
}

func (w *auditWriter) enqueueAccess(log *model.AccessLog) {
	select {
	case w.access <- log:
	default:
		w.recordDrop()
	}
}

func (w *auditWriter) enqueueAttack(log *model.AttackLog) {
	select {
	case w.attack <- log:
	default:
		w.recordDrop()
	}
}

func (w *auditWriter) recordDrop() {
	if count := w.dropped.Add(1); count == 1 || count%100 == 0 {
		logx.Warn("审计日志队列已满", "dropped_total", count)
	}
}

func (w *auditWriter) writeAccess() {
	defer w.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	batch := make([]*model.AccessLog, 0, 64)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if deadline := w.closeBy.Load(); deadline != 0 && time.Now().UnixNano() >= deadline {
			w.dropped.Add(uint64(len(batch)))
			batch = batch[:0]
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := w.accessRepo.InsertBatch(ctx, batch)
		cancel()
		if err != nil {
			w.failed.Add(uint64(len(batch)))
			logx.Error("访问日志批量写入失败", "count", len(batch), "err", err)
		}
		batch = batch[:0]
	}
	for {
		select {
		case log, ok := <-w.access:
			if !ok {
				flush()
				return
			}
			batch = append(batch, log)
			if len(batch) == cap(batch) {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (w *auditWriter) writeAttacks() {
	defer w.wg.Done()
	for log := range w.attack {
		if deadline := w.closeBy.Load(); deadline != 0 && time.Now().UnixNano() >= deadline {
			w.dropped.Add(1)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := w.attackRepo.UpsertAttack(ctx, log)
		cancel()
		if err != nil {
			w.failed.Add(1)
			logx.Error("攻击日志写入失败", "err", err)
		}
	}
}

// Close drains pending events for at most ten seconds after HTTP shutdown.
func (w *auditWriter) Close() {
	w.closeBy.Store(time.Now().Add(10 * time.Second).UnixNano())
	close(w.access)
	close(w.attack)
	w.wg.Wait()
}
