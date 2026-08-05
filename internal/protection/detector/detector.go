package detector

// 攻击检测器接口
// 各检测器实现本接口，由 protection.Engine 统一编排调用

import (
	"context"

	"jingshield/internal/protection/reqctx"
)

// Result 检测结果
type Result struct {
	Detected    bool   // 是否命中攻击
	AttackType  string // 攻击类型（对应 model 攻击类型常量）
	Detail      string // 攻击详情
	Code        int    // 错误码（对应 errx.CodeXSSAttack 等）
}

// Detector 检测器接口
type Detector interface {
	// Name 检测器名称
	Name() string
	// Check 执行检测
	Check(ctx context.Context, rc *reqctx.RequestContext) *Result
}
