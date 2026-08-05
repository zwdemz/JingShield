package iplist

// IP 管理服务：黑/白名单、海外 IP 拦截
// 对应 PHP CCProtection::checkBlacklistIP()/checkWhitelistIP()/checkOverseaIP()
//
// 安全改进：原 checkOverseaIP() 用硬编码 /8 段判断中国 IP，误杀严重；
// 本实现改用 QQWry 精准归属地，含"中国"关键字即为国内，否则视为海外。

import (
	"context"
	"strings"

	"jingshield/internal/config"
	"jingshield/internal/iplib"
	"jingshield/internal/repository"
)

// Service IP 管理服务
type Service struct {
	ipList  *repository.IPListRepo
	locator iplib.Locator
	dynCfg  *config.DynamicConfig
}

// New 构造 IP 管理服务
func New(ipList *repository.IPListRepo, locator iplib.Locator, dynCfg *config.DynamicConfig) *Service {
	return &Service{ipList: ipList, locator: locator, dynCfg: dynCfg}
}

// IsWhitelisted 是否白名单
// 对应 PHP checkWhitelistIP()
func (s *Service) IsWhitelisted(ctx context.Context, ip string) bool {
	ok, _ := s.ipList.IsWhitelisted(ctx, ip)
	return ok
}

// IsBlacklisted 是否黑名单（永久或未过期临时）
// 对应 PHP checkBlacklistIP()
func (s *Service) IsBlacklisted(ctx context.Context, ip string) bool {
	ok, _ := s.ipList.IsBlacklisted(ctx, ip)
	return ok
}

// IsOversea 是否海外 IP
// 对应 PHP checkOverseaIP()
// 改进：用 QQWry 精准归属地判断，替代原硬编码 /8 段
func (s *Service) IsOversea(ctx context.Context, ip string) bool {
	if !s.dynCfg.GetBool("oversea_ip_status") {
		return false
	}
	location := s.locator.Lookup(ip)
	if location == "" || location == "-" {
		// 查询失败，默认放行（避免误杀）
		return false
	}
	// 归属地含中国关键字即为国内
	chinaKeywords := []string{"中国", "中国大陆", "CN", "China"}
	for _, kw := range chinaKeywords {
		if strings.Contains(location, kw) {
			return false
		}
	}
	return true
}

// AddTempBlacklist 加入临时黑名单
// 对应 PHP addTempBlacklist()
func (s *Service) AddTempBlacklist(ctx context.Context, ip, reason string, expireSecs int) error {
	return s.ipList.AddTempBlacklist(ctx, ip, reason, expireSecs)
}
