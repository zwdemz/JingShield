package memory

// 内存状态存储实现
// 替代原 PHP 的 /cache/cc_*.txt 文件计数，进程内共享、零文件 IO
// 并发安全：每 key 独立互斥锁，sync.Map 管理索引

import (
	"context"
	"sync"
	"time"
)

// entry 滑动窗口计数条目（用于 HitAndCount）
type entry struct {
	mu         sync.Mutex
	timestamps []time.Time // 窗口内命中时刻
}

// ipEntry 单 IP 的行为状态条目
type ipEntry struct {
	mu          sync.Mutex
	lastRequest time.Time   // 上次请求时刻（checkRequestInterval）
	ports       []portHit   // 端口访问记录（checkPortScan）
	recentTimes []time.Time // 最近请求时刻（checkShieldBypass 方差分析）
}

// portHit 端口命中记录
type portHit struct {
	port int
	time time.Time
}

// Store 内存状态存储实现
type Store struct {
	windows sync.Map // map[string]*entry   —— 滑动窗口计数
	ips     sync.Map // map[string]*ipEntry —— 单 IP 行为状态
}

// New 构造内存存储
func New() *Store {
	return &Store{}
}

// StartGC 启动后台过期数据清理
// 每 interval 清理一次超时未活动的条目，防止内存无限增长
func (s *Store) StartGC(ctx context.Context, interval time.Duration, maxIdle time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.gc(maxIdle)
			}
		}
	}()
}

// gc 清理超时条目
func (s *Store) gc(maxIdle time.Duration) {
	now := time.Now()
	// 清理滑动窗口
	s.windows.Range(func(k, v any) bool {
		e := v.(*entry)
		e.mu.Lock()
		// 移除超过 maxIdle 的旧时间戳
		cutoff := now.Add(-maxIdle)
		kept := e.timestamps[:0]
		for _, t := range e.timestamps {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		e.timestamps = kept
		empty := len(e.timestamps) == 0
		e.mu.Unlock()
		if empty {
			s.windows.Delete(k)
		}
		return true
	})
	// 清理 IP 条目
	s.ips.Range(func(k, v any) bool {
		ie := v.(*ipEntry)
		ie.mu.Lock()
		idle := now.Sub(ie.lastRequest) > maxIdle
		ie.mu.Unlock()
		if idle {
			s.ips.Delete(k)
		}
		return true
	})
}

// getOrCreateEntry 获取或创建滑动窗口条目
func (s *Store) getOrCreateEntry(key string) *entry {
	v, _ := s.windows.LoadOrStore(key, &entry{})
	return v.(*entry)
}

// getOrCreateIPEntry 获取或创建 IP 行为条目
func (s *Store) getOrCreateIPEntry(ip string) *ipEntry {
	v, _ := s.ips.LoadOrStore(ip, &ipEntry{})
	return v.(*ipEntry)
}

// HitAndCount 命中并计数：记录当前时刻，返回窗口内命中次数
// 对应原 checkCCAttack()/checkURLFrequency() 的文件读写+时间过滤
func (s *Store) HitAndCount(_ context.Context, key string, windowSec int) (int, error) {
	e := s.getOrCreateEntry(key)
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Duration(windowSec) * time.Second)
	// 滑动窗口过滤：仅保留窗口内时间戳
	kept := e.timestamps[:0]
	for _, t := range e.timestamps {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	// 追加当前命中
	kept = append(kept, now)
	e.timestamps = kept
	return len(kept), nil
}

// LastRequestAt 记录并返回某 IP 上次请求时刻
// 对应原 checkRequestInterval() 的 cc_interval_*.txt
func (s *Store) LastRequestAt(_ context.Context, ip string) (time.Time, error) {
	ie := s.getOrCreateIPEntry(ip)
	ie.mu.Lock()
	defer ie.mu.Unlock()

	last := ie.lastRequest
	ie.lastRequest = time.Now()
	// 同时记录到 recentTimes 供方差分析
	ie.recentTimes = append(ie.recentTimes, time.Now())
	// 仅保留最近 20 条
	if len(ie.recentTimes) > 20 {
		ie.recentTimes = ie.recentTimes[len(ie.recentTimes)-20:]
	}
	return last, nil
}

// RecordPort 记录端口访问，返回窗口内不同端口数
// 对应原 checkPortScan() 的 cc_port_*.txt
func (s *Store) RecordPort(_ context.Context, ip string, port, windowSec int) (int, error) {
	ie := s.getOrCreateIPEntry(ip)
	ie.mu.Lock()
	defer ie.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Duration(windowSec) * time.Second)
	// 过滤窗口外记录
	kept := ie.ports[:0]
	for _, ph := range ie.ports {
		if ph.time.After(cutoff) {
			kept = append(kept, ph)
		}
	}
	// 追加当前端口（去重计数）
	kept = append(kept, portHit{port: port, time: now})
	ie.ports = kept

	// 统计不同端口数
	seen := make(map[int]struct{}, len(kept))
	for _, ph := range kept {
		seen[ph.port] = struct{}{}
	}
	return len(seen), nil
}

// RecentIntervals 取某 IP 最近 n 次请求的间隔时长（毫秒级）
// 对应原 checkShieldBypassAttack() 的标准差<0.3 判定数据源
func (s *Store) RecentIntervals(_ context.Context, ip string, n int) ([]time.Duration, error) {
	ie := getIPEntry(s, ip)
	if ie == nil {
		return nil, nil
	}
	ie.mu.Lock()
	defer ie.mu.Unlock()

	ts := ie.recentTimes
	if len(ts) < 2 {
		return nil, nil
	}
	// 取最近 n 条
	start := len(ts) - n
	if start < 0 {
		start = 0
	}
	recent := ts[start:]
	// 计算相邻间隔（最近在前，故 timestamps[i]-timestamps[i+1]）
	intervals := make([]time.Duration, 0, len(recent)-1)
	for i := 0; i < len(recent)-1; i++ {
		intervals = append(intervals, recent[i].Sub(recent[i+1]))
	}
	return intervals, nil
}

// getIPEntry 仅读取 IP 条目（不存在返回 nil）
func getIPEntry(s *Store, ip string) *ipEntry {
	v, ok := s.ips.Load(ip)
	if !ok {
		return nil
	}
	return v.(*ipEntry)
}

// ResetIP 清理某 IP 的全部临时状态
// 对应原 verify.php verificationSuccess() 的状态清理
func (s *Store) ResetIP(_ context.Context, ip string) error {
	// 清理 IP 维度滑动窗口（key=ip）
	s.windows.Delete(ip)
	// 清理 IP 行为条目
	s.ips.Delete(ip)
	// 清理 URL 维度滑动窗口（key 形如 ip|uri）
	prefix := ip + "|"
	s.windows.Range(func(k, v any) bool {
		if key, ok := k.(string); ok && len(key) > len(prefix) && key[:len(prefix)] == prefix {
			s.windows.Delete(k)
		}
		return true
	})
	return nil
}

// ClearAll 清空全部状态（后台清理缓存）
func (s *Store) ClearAll(_ context.Context) error {
	s.windows.Range(func(k, _ any) bool { s.windows.Delete(k); return true })
	s.ips.Range(func(k, _ any) bool { s.ips.Delete(k); return true })
	return nil
}
