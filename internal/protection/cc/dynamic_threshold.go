package cc

// 动态阈值：根据 CPU 负载动态调整防护阈值
// 对应 PHP CCProtection::getDynamicThreshold() + getCurrentCpuLoad()
//
// 原系统 getCurrentCpuLoad() 恒返回 0，动态阈值形同虚设。
// 本实现接 gopsutil 采集真实 CPU 使用率，使阈值在高负载时自动收紧。

import (
	"context"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
)

// CPU 采样配置
const (
	// cpuSampleInterval CPU 采样间隔（秒）
	cpuSampleInterval = 5
	// dynamicLoadThreshold 触发动态阈值的 CPU 负载阈值（%）
	dynamicLoadThreshold = 80.0
)

// cpuMonitor CPU 监控器（后台周期采样，缓存最近值）
type cpuMonitor struct {
	mu       sync.RWMutex
	usage    float64 // 最近一次 CPU 使用率（%）
	stopOnce sync.Once
}

var monitor = &cpuMonitor{}

// StartCPUMonitor 启动后台 CPU 采样协程
// 每 cpuSampleInterval 秒采样一次，缓存最近值供 getDynamicThreshold 使用
func StartCPUMonitor(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(cpuSampleInterval * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// 采样：interval=1 秒的瞬时使用率
				percent, err := cpu.Percent(time.Second, false)
				if err == nil && len(percent) > 0 {
					monitor.mu.Lock()
					monitor.usage = percent[0]
					monitor.mu.Unlock()
				}
			}
		}
	}()
}

// getCurrentCPULoad 获取当前 CPU 使用率（%）
// 对应 PHP getCurrentCpuLoad()，但返回真实值
func getCurrentCPULoad() float64 {
	monitor.mu.RLock()
	defer monitor.mu.RUnlock()
	return monitor.usage
}

// GetDynamicThreshold 动态阈值调整
// CPU 负载 >= dynamicLoadThreshold 时，阈值减半，收紧防护
// 对应 PHP getDynamicThreshold($base_value)
func GetDynamicThreshold(baseValue int) int {
	load := getCurrentCPULoad()
	if load >= dynamicLoadThreshold {
		// 高负载：阈值减半，至少为 1
		half := baseValue / 2
		if half < 1 {
			half = 1
		}
		return half
	}
	return baseValue
}
