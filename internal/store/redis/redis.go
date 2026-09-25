package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	redis "github.com/redis/go-redis/v9"
)

const prefix = "jingshield:state:"

var hitScript = redis.NewScript(`
local sequence = redis.call('INCR', KEYS[1] .. ':seq')
redis.call('PEXPIRE', KEYS[1] .. ':seq', ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[2])
redis.call('ZADD', KEYS[1], ARGV[1], sequence)
redis.call('PEXPIRE', KEYS[1], ARGV[3])
if KEYS[2] ~= '' then
  redis.call('SADD', KEYS[2], KEYS[1])
  redis.call('PEXPIRE', KEYS[2], ARGV[3])
end
return redis.call('ZCARD', KEYS[1])`)

var lastScript = redis.NewScript(`
local previous = redis.call('GET', KEYS[1])
redis.call('SET', KEYS[1], ARGV[1], 'EX', 600)
redis.call('LPUSH', KEYS[2], ARGV[1])
redis.call('LTRIM', KEYS[2], 0, 19)
redis.call('EXPIRE', KEYS[2], 600)
return previous`)

var portScript = redis.NewScript(`
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[2])
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[3])
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return redis.call('ZCARD', KEYS[1])`)

// Store shares CC counters and one-time challenges between WAF replicas.
type Store struct{ client *redis.Client }

// New checks that the configured Redis endpoint is available before accepting traffic.
func New(ctx context.Context, rawURL string) (*Store, error) {
	options, err := redis.ParseURL(rawURL)
	if err != nil {
		return nil, errors.New("Redis URL 无效")
	}
	client := redis.NewClient(options)
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := client.Ping(probe).Err(); err != nil {
		_ = client.Close()
		return nil, errors.New("Redis 连接失败")
	}
	return &Store{client: client}, nil
}

// Close releases Redis connections.
func (s *Store) Close() error { return s.client.Close() }

func key(kind, value string) string {
	digest := sha256.Sum256([]byte(value))
	return prefix + kind + ":" + hex.EncodeToString(digest[:])
}

// HitAndCount atomically records a hit and returns the sliding-window count.
func (s *Store) HitAndCount(ctx context.Context, value string, windowSec int) (int, error) {
	if windowSec < 1 {
		windowSec = 1
	}
	index := ""
	if separator := strings.IndexByte(value, '|'); separator > 0 {
		index = key("index", value[:separator])
	}
	now := time.Now().UnixMilli()
	count, err := hitScript.Run(ctx, s.client, []string{key("window", value), index}, now, now-int64(windowSec)*1000, max(windowSec*1000, 600000)).Int()
	return count, err
}

// LastRequestAt atomically records the current request and returns the preceding timestamp.
func (s *Store) LastRequestAt(ctx context.Context, ip string) (time.Time, error) {
	previous, err := lastScript.Run(ctx, s.client, []string{key("last", ip), key("recent", ip)}, time.Now().UnixMilli()).Text()
	if errors.Is(err, redis.Nil) || previous == "" {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	milliseconds, err := strconv.ParseInt(previous, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(milliseconds), nil
}

// RecordPort returns the number of distinct ports seen during the window.
func (s *Store) RecordPort(ctx context.Context, ip string, port, windowSec int) (int, error) {
	if windowSec < 1 {
		windowSec = 1
	}
	now := time.Now().UnixMilli()
	return portScript.Run(ctx, s.client, []string{key("ports", ip)}, now, now-int64(windowSec)*1000, port, windowSec*1000).Int()
}

// RecentIntervals returns consecutive request intervals, newest first.
func (s *Store) RecentIntervals(ctx context.Context, ip string, count int) ([]time.Duration, error) {
	if count < 2 {
		return nil, nil
	}
	values, err := s.client.LRange(ctx, key("recent", ip), 0, int64(count-1)).Result()
	if err != nil {
		return nil, err
	}
	intervals := make([]time.Duration, 0, len(values)-1)
	for index := 0; index+1 < len(values); index++ {
		newer, errNew := strconv.ParseInt(values[index], 10, 64)
		older, errOld := strconv.ParseInt(values[index+1], 10, 64)
		if errNew != nil || errOld != nil {
			return nil, errors.New("Redis 时间状态无效")
		}
		intervals = append(intervals, time.Duration(newer-older)*time.Millisecond)
	}
	return intervals, nil
}

// ResetIP clears one client's counters after successful verification.
func (s *Store) ResetIP(ctx context.Context, ip string) error {
	index := key("index", ip)
	keys, err := s.client.SMembers(ctx, index).Result()
	if err != nil {
		return err
	}
	keys = append(keys, index, key("window", ip), key("window", ip)+":seq", key("last", ip), key("recent", ip), key("ports", ip))
	return s.client.Del(ctx, keys...).Err()
}

// ClearAll clears only JingShield state keys, leaving other Redis applications untouched.
func (s *Store) ClearAll(ctx context.Context) error {
	iterator := s.client.Scan(ctx, 0, prefix+"*", 100).Iterator()
	for iterator.Next(ctx) {
		if err := s.client.Unlink(ctx, iterator.Val()).Err(); err != nil {
			return err
		}
	}
	return iterator.Err()
}

// PutChallenge stores a challenge nonce until its expiry.
func (s *Store) PutChallenge(ctx context.Context, nonce string, payload []byte, ttl time.Duration) error {
	return s.client.Set(ctx, key("challenge", nonce), payload, ttl).Err()
}

// ConsumeChallenge atomically removes a challenge, enforcing single use across replicas.
func (s *Store) ConsumeChallenge(ctx context.Context, nonce string) ([]byte, error) {
	result, err := s.client.GetDel(ctx, key("challenge", nonce)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	return result, err
}
