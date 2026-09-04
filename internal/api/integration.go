package api

import (
	"net/http"
	"strings"
	"time"

	"jingshield/internal/model"
	"jingshield/internal/pkg/iputil"
)

func (a *API) integrationGet(w http.ResponseWriter, _ *http.Request) {
	key := a.dynamic.Get("api_key")
	masked := ""
	if len(key) >= 6 {
		masked = "••••••••••••" + key[len(key)-6:]
	}
	writeOK(w, "success", map[string]any{
		"enabled":        a.dynamic.GetIntDefault("api_enabled", 1) == 1,
		"key_configured": key != "",
		"key_masked":     masked,
		"header":         "X-API-Key",
		"endpoints": []map[string]string{
			{"method": "GET", "path": "/openapi/v1/status", "description": "读取节点与站点状态"},
			{"method": "POST", "path": "/openapi/v1/ip/block", "description": "永久或临时封禁 IP"},
			{"method": "POST", "path": "/openapi/v1/ip/unblock", "description": "解除 IP 黑名单"},
			{"method": "POST", "path": "/openapi/v1/events/{format}", "description": "接收 CEF、LEEF、Suricata、Wazuh 或通用 JSON 事件"},
		},
	})
}

func (a *API) integrationStatusPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if decodeJSON(w, r, &in) != nil {
		writeError(w, http.StatusBadRequest, -3, "联动状态参数非法")
		return
	}
	value := "0"
	if in.Enabled {
		value = "1"
	}
	if err := a.dynamic.Set(r.Context(), "api_enabled", value); err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "API 联动状态已更新", nil)
}

func (a *API) integrationKeyRotate(w http.ResponseWriter, r *http.Request) {
	key, err := randomToken(32)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	if err := a.dynamic.Set(r.Context(), "api_key", key); err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "API Key 已轮换；旧密钥立即失效，请妥善保存新密钥", map[string]string{"api_key": key})
}

func (a *API) openAPIOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.dynamic.GetIntDefault("api_enabled", 1) != 1 {
			writeError(w, http.StatusServiceUnavailable, -503, "API 联动已停用")
			return
		}
		configuredKey := a.dynamic.Get("api_key")
		clientIP := iputil.GetClientIP(r, a.trusted)
		if configuredKey == "" || (a.apiLimiter != nil && !a.apiLimiter.allow(clientIP, time.Now())) {
			writeError(w, http.StatusUnauthorized, -401, "API Key 无效")
			return
		}
		if !constantEqual(r.Header.Get("X-API-Key"), configuredKey) {
			writeError(w, http.StatusUnauthorized, -401, "API Key 无效")
			return
		}
		if a.apiLimiter != nil {
			a.apiLimiter.reset(clientIP)
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) openAPIStatus(w http.ResponseWriter, r *http.Request) {
	sites, err := a.sites.List(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	enabled := 0
	for _, site := range sites {
		if site.Enabled {
			enabled++
		}
	}
	writeOK(w, "success", map[string]any{
		"service": "JingShield", "status": "healthy", "waf_enabled": a.dynamic.GetBool("system_status"),
		"sites_total": len(sites), "sites_enabled": enabled, "server_time": time.Now().UTC().Format(time.RFC3339),
	})
}

func (a *API) openAPIBlockIP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IP            string `json:"ip"`
		Reason        string `json:"reason"`
		ExpireSeconds int    `json:"expire_seconds"`
	}
	if decodeJSON(w, r, &in) != nil {
		writeError(w, http.StatusBadRequest, -3, "请求参数格式错误")
		return
	}
	in.IP, in.Reason = strings.TrimSpace(in.IP), strings.TrimSpace(in.Reason)
	if !validIPRule(in.IP) || len(in.Reason) > 255 || in.ExpireSeconds < 0 || in.ExpireSeconds > 31536000 {
		writeError(w, http.StatusBadRequest, -3, "IP、原因或有效期参数非法")
		return
	}
	if in.Reason == "" {
		in.Reason = "外部 API 联动封禁"
	}
	if _, err := a.ipList.DeleteByIP(r.Context(), in.IP); err != nil {
		a.internalError(w, r, err)
		return
	}
	typ := model.IPTypeBlacklist
	var expires *time.Time
	if in.ExpireSeconds > 0 {
		typ = model.IPTypeTempBlacklist
		t := time.Now().Add(time.Duration(in.ExpireSeconds) * time.Second)
		expires = &t
	}
	if err := a.ipList.Add(r.Context(), in.IP, typ, in.Reason, expires); err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "IP 已加入黑名单", map[string]any{"ip": in.IP, "type": typ, "expire_seconds": in.ExpireSeconds})
}

func (a *API) openAPIUnblockIP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IP string `json:"ip"`
	}
	if decodeJSON(w, r, &in) != nil {
		writeError(w, http.StatusBadRequest, -3, "请求参数格式错误")
		return
	}
	in.IP = strings.TrimSpace(in.IP)
	if !validIPRule(in.IP) {
		writeError(w, http.StatusBadRequest, -3, "IP 参数非法")
		return
	}
	removed, err := a.ipList.DeleteByIP(r.Context(), in.IP)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "IP 黑名单已解除", map[string]any{"ip": in.IP, "removed": removed})
}
