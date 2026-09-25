package redis

import (
	"context"
	"errors"
	"strconv"

	"jingshield/internal/store"

	redis "github.com/redis/go-redis/v9"
)

// Server time makes the shared sliding window independent of replica clock drift.
// One hash-slot tag keeps this atomic script compatible with Redis Cluster keys.
var behaviorScript = redis.NewScript(`
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local window = tonumber(ARGV[3]) * 1000
local threshold = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5]) * 1000
local enforce = ARGV[6] == '1'
local remaining = redis.call('PTTL', KEYS[3])
if enforce and remaining > 0 then
  return {0, 0, 1, 1, math.ceil(remaining / 1000)}
end
if ARGV[1] == '' then return {0, 0, 0, 0, 0} end
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now - window)
local sequence = redis.call('INCR', KEYS[4])
redis.call('PEXPIRE', KEYS[4], window)
redis.call('ZADD', KEYS[1], now, sequence)
local count = redis.call('ZCARD', KEYS[1])
if count > 2 * threshold then
  redis.call('ZREMRANGEBYRANK', KEYS[1], 0, count - 2 * threshold - 1)
  count = 2 * threshold
end
redis.call('ZADD', KEYS[2], now, ARGV[1])
redis.call('PEXPIRE', KEYS[1], window)
redis.call('PEXPIRE', KEYS[2], window)
local distinct = redis.call('ZCARD', KEYS[2])
local matched = count >= threshold and (distinct >= 2 or ARGV[2] == '1' or count >= 2 * threshold)
if matched and enforce then
  redis.call('SET', KEYS[3], '1', 'PX', ttl)
  redis.call('DEL', KEYS[1], KEYS[2], KEYS[4])
  return {count, distinct, 1, 1, math.ceil(ttl / 1000)}
end
return {count, distinct, matched and 1 or 0, 0, 0}
`)

// ObserveBehavior atomically shares a scoped sliding window and fixed block TTL.
// Empty categories check existing blocks only; observe mode never creates or
// enforces blocks. Invalid input, Redis failures or malformed replies return errors.
func (s *Store) ObserveBehavior(ctx context.Context, scope, category string, scannerClient bool, policy store.BehaviorPolicy, enforce bool) (store.BehaviorSnapshot, error) {
	var snapshot store.BehaviorSnapshot
	if err := store.ValidateBehaviorInput(scope, category, policy); err != nil {
		return snapshot, err
	}
	base := prefix + "behavior:{" + key("scope", scope)[len(prefix)+len("scope:"):] + "}"
	values, err := behaviorScript.Run(ctx, s.client, []string{base + ":hits", base + ":categories", base + ":block", base + ":sequence"}, category, behaviorFlag(scannerClient), policy.WindowSeconds, policy.Threshold, policy.BlockSeconds, behaviorFlag(enforce)).Slice()
	if err != nil {
		return snapshot, err
	}
	if len(values) != 5 {
		return snapshot, errors.New("invalid Redis behavior response")
	}
	numbers := make([]int, len(values))
	for index, value := range values {
		switch number := value.(type) {
		case int64:
			numbers[index] = int(number)
		case string:
			parsed, parseErr := strconv.Atoi(number)
			if parseErr != nil {
				return snapshot, errors.New("invalid Redis behavior counter")
			}
			numbers[index] = parsed
		default:
			return snapshot, errors.New("invalid Redis behavior value")
		}
	}
	return store.BehaviorSnapshot{Hits: numbers[0], DistinctCategories: numbers[1], Matched: numbers[2] != 0, Blocked: numbers[3] != 0, BlockRemainingSeconds: numbers[4]}, nil
}

func behaviorFlag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
