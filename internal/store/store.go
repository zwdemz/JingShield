package store

// 状态存储接口：替代原 PHP 的文件 IPC（/cache/cc_*.txt）
//
// 原系统因 PHP-FPM 进程无共享内存，CC 频率/区间/端口计数器
// 全部写成 JSON 文件。Go 长驻进程可内存共享，故用内存实现，
// 通过本接口抽象以便未来切换 Redis（多副本共享计数）。

import (
	"context"
	"time"
)

// StateStore 防护状态存储接口
type StateStore interface {
	// HitAndCount 命中并计数：记录当前时刻，返回 key 在 windowSec 时间窗口内的命中次数
	// 对应原 checkCCAttack()/checkURLFrequency() 的文件读写+过滤逻辑
	HitAndCount(ctx context.Context, key string, windowSec int) (count int, err error)

	// LastRequestAt 记录并返回某 IP 上次请求时刻
	// 对应原 checkRequestInterval() 的 cc_interval_*.txt
	LastRequestAt(ctx context.Context, ip string) (last time.Time, err error)

	// RecordPort 记录端口访问，返回窗口内不同端口数
	// 对应原 checkPortScan() 的 cc_port_*.txt
	RecordPort(ctx context.Context, ip string, port, windowSec int) (distinctPorts int, err error)

	// RecentIntervals 取某 IP 最近 n 次请求的间隔时长（用于方差分析）
	// 对应原 checkShieldBypassAttack() 的标准差计算数据源
	RecentIntervals(ctx context.Context, ip string, n int) ([]time.Duration, error)

	// ResetIP 清理某 IP 的全部临时状态（验证成功后调用）
	// 对应原 verify.php verificationSuccess() 的状态清理
	ResetIP(ctx context.Context, ip string) error

	// ClearAll 清空全部状态（后台清理缓存）
	ClearAll(ctx context.Context) error
}
