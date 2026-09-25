package api

import (
	"context"
	"errors"
	"jingshield/internal/repository"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// applyAttackIPFilter only creates bound numeric ranges, never SQL fragments.
// Prefix mode respects octet/hextet boundaries and canonical IPv6 addresses.
func applyAttackIPFilter(filter *repository.AttackLogFilter, mode string) error {
	if mode == "" {
		mode = "exact"
	}
	if mode != "exact" && mode != "prefix" && mode != "cidr" {
		return errors.New("IP 检索模式非法")
	}
	if filter.IP == "" {
		return nil
	}
	if mode == "exact" {
		address, err := netip.ParseAddr(filter.IP)
		if err != nil || address.Zone() != "" {
			return errors.New("请输入完整 IPv4/IPv6 地址")
		}
		filter.IP = address.Unmap().String()
		return nil
	}
	value := filter.IP
	if mode == "prefix" {
		if strings.HasSuffix(value, ".") {
			parts := strings.Split(strings.TrimSuffix(value, "."), ".")
			if len(parts) < 1 || len(parts) > 3 {
				return errors.New("IPv4 前缀应为 1-3 个完整段并以点结尾")
			}
			for _, part := range parts {
				n, err := strconv.Atoi(part)
				if err != nil || n < 0 || n > 255 || strconv.Itoa(n) != part {
					return errors.New("IPv4 前缀非法")
				}
			}
			value = strings.Join(parts, ".") + strings.Repeat(".0", 4-len(parts)) + "/" + strconv.Itoa(len(parts)*8)
		} else if strings.HasSuffix(value, ":") {
			prefix := strings.TrimRight(value, ":")
			parts := strings.Split(prefix, ":")
			if strings.Contains(prefix, "::") || len(parts) < 1 || len(parts) > 7 {
				return errors.New("压缩 IPv6 前缀请改用 CIDR 模式")
			}
			for _, part := range parts {
				if len(part) < 1 || len(part) > 4 {
					return errors.New("IPv6 前缀非法")
				}
				if _, err := strconv.ParseUint(part, 16, 16); err != nil {
					return errors.New("IPv6 前缀非法")
				}
			}
			value = prefix + "::/" + strconv.Itoa(len(parts)*16)
		} else {
			return errors.New("前缀须以 IPv4 点或 IPv6 冒号边界结尾，也可使用 CIDR 模式")
		}
	}
	network, err := netip.ParsePrefix(value)
	if err != nil || network.Addr().Is4In6() {
		return errors.New("IP 网段格式非法；映射 IPv4 请用原生 IPv4 网段")
	}
	network = network.Masked()
	first := network.Addr()
	bytes := first.AsSlice()
	for bit := network.Bits(); bit < len(bytes)*8; bit++ {
		bytes[bit/8] |= 1 << (7 - uint(bit%8))
	}
	last, ok := netip.AddrFromSlice(bytes)
	if !ok {
		return errors.New("IP 网段格式非法")
	}
	filter.IP = ""
	filter.IPFrom, filter.IPTo = first.String(), last.String()
	return nil
}

func (a *API) attackIPSummary(w http.ResponseWriter, r *http.Request) {
	filter, err := attackFilter(r)
	if err != nil {
		writeError(w, 400, -3, err.Error())
		return
	}
	if filter.IP == "" {
		writeError(w, 400, -3, "IP 画像需要一个完整 IPv4/IPv6 地址")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	summary, err := a.attacks.IPSummary(ctx, filter)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	blacklisted, err := a.ipList.IsBlacklisted(ctx, filter.IP)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	if blacklisted {
		summary.ListStatus = "blacklist"
	} else {
		whitelisted, err := a.ipList.IsWhitelisted(ctx, filter.IP)
		if err != nil {
			a.internalError(w, r, err)
			return
		}
		if whitelisted {
			summary.ListStatus = "whitelist"
		}
	}
	writeOK(w, "success", summary)
}
