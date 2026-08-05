package cc

// URL 频率检测、请求间隔检测、端口扫描检测
// 对应 PHP checkURLFrequency() / checkRequestInterval() / checkPortScan()
// 原系统用文件存储，本实现用内存 Store

import (
	"context"
	"strconv"
	"time"

	"jingshield/internal/protection/reqctx"
)

// 频率/间隔/端口检测参数
const (
	urlFreqWindow          = 60   // URL 频率检测窗口（秒）
	urlFreqThreshold       = 20   // 单 URL 窗口内最大访问次数
	reqIntervalThresholdMs = 500  // 最小请求间隔（毫秒），低于此值疑似高频攻击
	portScanWindow         = 60   // 端口扫描检测窗口（秒）
	portScanThreshold      = 5    // 窗口内不同端口数阈值
)

// checkURLFrequency 检测单 URL 访问频率
// 对应 PHP checkURLFrequency()
// key 为 ip+uri，统计窗口内访问次数
func (d *CCDetector) checkURLFrequency(ctx context.Context, rc *reqctx.RequestContext) bool {
	key := rc.IP + "|" + rc.URI
	count, _ := d.store.HitAndCount(ctx, key, urlFreqWindow)
	effective := GetDynamicThreshold(urlFreqThreshold)
	return count > effective
}

// checkRequestInterval 检测请求间隔是否过小
// 对应 PHP checkRequestInterval()
// 取上次请求时刻，计算间隔，小于动态阈值则判定为高频
func (d *CCDetector) checkRequestInterval(ctx context.Context, rc *reqctx.RequestContext) bool {
	last, err := d.store.LastRequestAt(ctx, rc.IP)
	if err != nil || last.IsZero() {
		// 首次请求不判定
		return false
	}
	// 间隔毫秒
	intervalMs := time.Since(last).Milliseconds()
	if intervalMs == 0 {
		return false
	}
	effective := int64(GetDynamicThreshold(reqIntervalThresholdMs))
	return intervalMs < effective
}

// checkPortScan 检测端口扫描行为
// 对应 PHP checkPortScan()
// 统计窗口内访问的不同端口数
func (d *CCDetector) checkPortScan(ctx context.Context, rc *reqctx.RequestContext) bool {
	portStr := rc.R.URL.Port()
	if portStr == "" {
		// 从 TLS 状态推断默认端口
		portStr = "80"
		if rc.R.TLS != nil {
			portStr = "443"
		}
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum == 0 {
		return false
	}
	distinct, _ := d.store.RecordPort(ctx, rc.IP, portNum, portScanWindow)
	return distinct >= portScanThreshold
}
