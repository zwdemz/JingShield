package api

import (
	"encoding/base64"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"jingshield/internal/model"
	"jingshield/internal/policy"
	"jingshield/internal/repository"
)

const maxPolicyImportBody = 2 << 20

func (a *API) policyList(w http.ResponseWriter, r *http.Request) {
	list, err := a.policies.List(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "success", list)
}

func (a *API) policyCreate(w http.ResponseWriter, r *http.Request) {
	var input policy.RuleInput
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, -3, "策略参数格式错误")
		return
	}
	rule, err := a.policies.Create(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusBadRequest, -3, err.Error())
		return
	}
	writeOK(w, "自定义策略已创建并热加载", rule)
}

func (a *API) policyUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := policyID(w, r)
	if !ok {
		return
	}
	var input policy.RuleInput
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, -3, "策略参数格式错误")
		return
	}
	rule, err := a.policies.Update(r.Context(), id, "custom", "1", input)
	if errors.Is(err, repository.ErrPolicyNotFound) {
		writeError(w, http.StatusNotFound, -404, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, -3, err.Error())
		return
	}
	writeOK(w, "策略已更新并热加载", rule)
}

func (a *API) policyDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := policyID(w, r)
	if !ok {
		return
	}
	if err := a.policies.Delete(r.Context(), id); errors.Is(err, repository.ErrPolicyNotFound) {
		writeError(w, http.StatusNotFound, -404, err.Error())
		return
	} else if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "策略已删除", nil)
}

func policyID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, -3, "策略 ID 非法")
		return 0, false
	}
	return id, true
}

func (a *API) policyImport(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, -3, "规则包只接受 application/json")
		return
	}
	var pack policy.RulePack
	if err := decodeJSONLimit(w, r, &pack, maxPolicyImportBody); err != nil {
		var sizeError *http.MaxBytesError
		if errors.As(err, &sizeError) {
			writeError(w, http.StatusRequestEntityTooLarge, -3, "规则包不能超过 2MB")
			return
		}
		writeError(w, http.StatusBadRequest, -3, "规则包 JSON 格式错误")
		return
	}
	count, err := a.policies.Import(r.Context(), pack, "import")
	if err != nil {
		writeError(w, http.StatusBadRequest, -3, err.Error())
		return
	}
	writeOK(w, "规则包已导入并热加载", map[string]any{"version": pack.Version, "count": count})
}

func (a *API) policySettingsGet(w http.ResponseWriter, r *http.Request) {
	counts, err := repository.NewPolicyRepo(a.db).CountBySource(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "success", map[string]any{
		"auto_update": a.dynamic.GetBool("policy_auto_update"), "url": a.dynamic.Get("policy_update_url"),
		"interval_minutes":      a.dynamic.GetIntDefault("policy_update_interval_minutes", 360),
		"public_key_configured": a.dynamic.Get("policy_update_public_key") != "", "last_version": a.dynamic.Get("policy_last_version"),
		"last_update": a.dynamic.Get("policy_last_update"), "last_error": a.dynamic.Get("policy_last_error"), "counts": counts,
	})
}

func (a *API) policySettingsPut(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AutoUpdate      bool   `json:"auto_update"`
		URL             string `json:"url"`
		IntervalMinutes int    `json:"interval_minutes"`
		PublicKey       string `json:"public_key"`
	}
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, -3, "自动更新参数格式错误")
		return
	}
	input.URL, input.PublicKey = strings.TrimSpace(input.URL), strings.TrimSpace(input.PublicKey)
	// The API never returns the key material. An empty field therefore means
	// "keep the currently pinned key", which makes settings edits safe.
	if input.PublicKey == "" {
		input.PublicKey = a.dynamic.Get("policy_update_public_key")
	}
	if input.IntervalMinutes < 5 || input.IntervalMinutes > 10080 || len(input.URL) > 2048 {
		writeError(w, http.StatusBadRequest, -3, "更新间隔或 URL 非法")
		return
	}
	if input.URL != "" {
		parsed, err := url.Parse(input.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
			writeError(w, http.StatusBadRequest, -3, "更新地址必须是无账号信息的 HTTPS URL")
			return
		}
	}
	if input.PublicKey != "" {
		key, err := decodeEd25519PublicKey(input.PublicKey)
		if err != nil || len(key) != 32 {
			writeError(w, http.StatusBadRequest, -3, "Ed25519 公钥必须是 32 字节 Base64 或 Base64URL")
			return
		}
	}
	if input.AutoUpdate && (input.URL == "" || input.PublicKey == "") {
		writeError(w, http.StatusBadRequest, -3, "启用自动更新前必须配置 HTTPS URL 和 Ed25519 公钥")
		return
	}
	values := map[string]string{"policy_auto_update": boolString(input.AutoUpdate), "policy_update_url": input.URL, "policy_update_interval_minutes": strconv.Itoa(input.IntervalMinutes), "policy_update_public_key": input.PublicKey}
	for key, value := range values {
		if err := a.dynamic.Set(r.Context(), key, value); err != nil {
			a.internalError(w, r, err)
			return
		}
	}
	writeOK(w, "策略自动更新配置已保存", nil)
}

func decodeEd25519PublicKey(value string) ([]byte, error) {
	if key, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return key, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

func (a *API) policyUpdateNow(w http.ResponseWriter, r *http.Request) {
	version, count, err := a.policies.UpdateNow(r.Context())
	if err != nil {
		_ = a.dynamic.Set(r.Context(), "policy_last_error", err.Error())
		writeError(w, http.StatusBadGateway, -1, err.Error())
		return
	}
	writeOK(w, "签名策略包已更新", map[string]any{"version": version, "count": count})
}

func (a *API) policyRecommendations(w http.ResponseWriter, r *http.Request) {
	attackCounts, err := a.attacks.TodayCountByType(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	rate, err := a.accessLogs.CountLastMinute(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	recommendations := make([]map[string]any, 0)
	checks := []struct{ key, label, attackType string }{{"xss_protection_status", "启用 XSS 检测", model.AttackTypeXSS}, {"sql_protection_status", "启用 SQL 注入检测", model.AttackTypeSQL}, {"cc_protection_status", "启用 CC 防护", model.AttackTypeCC}}
	for _, check := range checks {
		if a.dynamic.GetInt(check.key) == 0 {
			recommendations = append(recommendations, map[string]any{"id": "enable-" + check.key, "title": check.label, "reason": "对应防护当前关闭，今日关联事件 " + strconv.FormatInt(attackCounts[check.attackType], 10) + " 次", "config_key": check.key, "current": 0, "recommended": 1, "risk": "high"})
		}
	}
	ccLimit := a.dynamic.GetIntDefault("cc_visit_count", 100)
	if int(rate) >= ccLimit*8/10 {
		recommended := int(rate) * 2
		if recommended < ccLimit+20 {
			recommended = ccLimit + 20
		}
		recommendations = append(recommendations, map[string]any{"id": "tune-cc-rate", "title": "校准 CC 访问阈值", "reason": "当前业务速率已接近 CC 阈值，建议留出突发余量", "config_key": "cc_visit_count", "current": ccLimit, "recommended": recommended, "risk": "medium"})
	}
	if len(recommendations) == 0 {
		recommendations = append(recommendations, map[string]any{"id": "healthy", "title": "当前策略无需调整", "reason": "防护开关与最近一分钟业务速率未发现明显配置冲突", "risk": "low"})
	}
	writeOK(w, "success", map[string]any{"generated_at": time.Now().UTC().Format(time.RFC3339), "request_rate": rate, "recommendations": recommendations})
}

func (a *API) policyRecommendationApply(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ConfigKey string `json:"config_key"`
		Value     int    `json:"value"`
	}
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, -3, "优化建议参数错误")
		return
	}
	value := strconv.Itoa(input.Value)
	allowed := map[string]bool{"xss_protection_status": true, "sql_protection_status": true, "cc_protection_status": true, "cc_visit_count": true}
	if !allowed[input.ConfigKey] || !validDynamicConfig(input.ConfigKey, value) {
		writeError(w, http.StatusBadRequest, -3, "不支持应用该优化项")
		return
	}
	if err := a.dynamic.Set(r.Context(), input.ConfigKey, value); err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "策略优化建议已应用", nil)
}

func boolString(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
