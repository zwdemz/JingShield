package cc

// TCP 连接攻击检测
// 对应 PHP CCProtection::checkTCPAttack()
// 统计某 IP 在短时间窗口内的访问次数，超阈值判定为 TCP 攻击

import (
	"context"
	"time"

	"jingshield/internal/protection/reqctx"
)

// TCP 检测参数（对应 PHP 硬编码常量）
const (
	tcpCheckTime       = 5  // 检测窗口（秒）
	tcpMaxConnections  = 20 // 基础最大连接阈值
)

// checkTCP 检测 TCP 连接攻击
// 对应 PHP checkTCPAttack()
func (d *CCDetector) checkTCP(ctx context.Context, rc *reqctx.RequestContext) bool {
	if !d.dynCfg.GetBool("cc_protection_status") {
		return false
	}

	// 动态阈值
	effectiveMax := GetDynamicThreshold(tcpMaxConnections)

	// 查询 access_log 在窗口内的访问次数
	since := time.Now().Add(-tcpCheckTime * time.Second).Format("2006-01-02 15:04:05")
	count, err := d.accessLog.CountByIPSince(ctx, rc.IP, since)
	if err != nil {
		return false
	}
	return count > int64(effectiveMax)
}
