package api

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"jingshield/internal/config"
	"jingshield/internal/model"
	"jingshield/internal/pkg/iputil"
	"jingshield/internal/pkg/logx"
	"jingshield/internal/policy"
	"jingshield/internal/repository"
	"jingshield/internal/store"
)

const maxJSONBody = 1 << 20

type Dependencies struct {
	DB              *sql.DB
	DynamicConfig   *config.DynamicConfig
	State           store.StateStore
	StaticConfig    *config.Config
	Sites           *repository.SiteRepo
	Policies        *policy.Service
	AdminHandler    http.Handler
	FallbackHandler http.Handler
}

type API struct {
	db           *sql.DB
	users        *repository.UserRepo
	loginLogs    *repository.LoginLogRepo
	accessLogs   *repository.AccessLogRepo
	attacks      *repository.AttackLogRepo
	ipList       *repository.IPListRepo
	configs      *repository.ConfigRepo
	sites        *repository.SiteRepo
	dynamic      *config.DynamicConfig
	state        store.StateStore
	sessions     *sessionManager
	adminIPs     []string
	trusted      []string
	fallback     http.Handler
	logDir       string
	policies     *policy.Service
	deviceEvents *repository.DeviceEventRepo
}

type sessionContextKey struct{}

func New(deps Dependencies) (http.Handler, error) {
	if deps.DB == nil || deps.DynamicConfig == nil || deps.State == nil || deps.StaticConfig == nil || deps.Sites == nil || deps.Policies == nil || deps.FallbackHandler == nil {
		return nil, errors.New("管理 API 依赖不完整")
	}
	a := &API{
		db:    deps.DB,
		users: repository.NewUserRepo(deps.DB), loginLogs: repository.NewLoginLogRepo(deps.DB),
		accessLogs: repository.NewAccessLogRepo(deps.DB), attacks: repository.NewAttackLogRepo(deps.DB),
		ipList: repository.NewIPListRepo(deps.DB), configs: repository.NewConfigRepo(deps.DB),
		dynamic: deps.DynamicConfig, state: deps.State, sites: deps.Sites, sessions: newSessionManager(deps.StaticConfig.Session),
		adminIPs: deps.StaticConfig.AdminIPs, trusted: deps.StaticConfig.Server.TrustedProxies,
		fallback: deps.FallbackHandler, logDir: deps.StaticConfig.Log.Dir, policies: deps.Policies,
		deviceEvents: repository.NewDeviceEventRepo(deps.DB),
	}

	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/auth/login", a.adminOnly(http.HandlerFunc(a.login)))
	mux.Handle("POST /api/v1/auth/logout", a.protected(http.HandlerFunc(a.logout), true, true))
	mux.Handle("GET /api/v1/auth/me", a.protected(http.HandlerFunc(a.me), true, false))
	mux.Handle("GET /api/v1/dashboard/stats", a.protected(http.HandlerFunc(a.dashboardStats), false, false))
	mux.Handle("GET /api/v1/dashboard/trend", a.protected(http.HandlerFunc(a.dashboardTrend), false, false))
	mux.Handle("GET /api/v1/dashboard/top-ips", a.protected(http.HandlerFunc(a.dashboardTopIPs), false, false))
	mux.Handle("GET /api/v1/attacks", a.protected(http.HandlerFunc(a.attackList), false, false))
	mux.Handle("GET /api/v1/attacks/export", a.protected(http.HandlerFunc(a.attackExport), false, false))
	mux.Handle("GET /api/v1/access-logs", a.protected(http.HandlerFunc(a.accessLogList), false, false))
	mux.Handle("GET /api/v1/login-logs", a.protected(http.HandlerFunc(a.loginLogList), false, false))
	mux.Handle("GET /api/v1/ip-list", a.protected(http.HandlerFunc(a.ipListGet), false, false))
	mux.Handle("POST /api/v1/ip-list", a.protected(http.HandlerFunc(a.ipListAdd), false, true))
	mux.Handle("DELETE /api/v1/ip-list/{id}", a.protected(http.HandlerFunc(a.ipListDelete), false, true))
	mux.Handle("GET /api/v1/config", a.protected(http.HandlerFunc(a.configGet), false, false))
	mux.Handle("PUT /api/v1/config", a.protected(http.HandlerFunc(a.configPut), false, true))
	mux.Handle("GET /api/v1/system/status", a.protected(http.HandlerFunc(a.systemStatusGet), false, false))
	mux.Handle("PUT /api/v1/system/status", a.protected(http.HandlerFunc(a.systemStatusPut), false, true))
	mux.Handle("GET /api/v1/system/resources", a.protected(http.HandlerFunc(a.systemResourcesGet), false, false))
	mux.Handle("PUT /api/v1/system/alert-thresholds", a.protected(http.HandlerFunc(a.alertThresholdsPut), false, true))
	mux.Handle("DELETE /api/v1/cache", a.protected(http.HandlerFunc(a.cacheDelete), false, true))
	mux.Handle("PUT /api/v1/users/password", a.protected(http.HandlerFunc(a.passwordPut), true, true))
	mux.Handle("GET /api/v1/users", a.protected(http.HandlerFunc(a.userList), false, false))
	mux.Handle("POST /api/v1/users", a.protected(http.HandlerFunc(a.userCreate), false, true))
	mux.Handle("PUT /api/v1/users/{id}/status", a.protected(http.HandlerFunc(a.userStatusPut), false, true))
	mux.Handle("PUT /api/v1/users/{id}/password", a.protected(http.HandlerFunc(a.userPasswordReset), false, true))
	mux.Handle("GET /api/v1/integration", a.protected(http.HandlerFunc(a.integrationGet), false, false))
	mux.Handle("PUT /api/v1/integration/status", a.protected(http.HandlerFunc(a.integrationStatusPut), false, true))
	mux.Handle("POST /api/v1/integration/api-key/rotate", a.protected(http.HandlerFunc(a.integrationKeyRotate), false, true))
	mux.Handle("GET /api/v1/integration/device-settings", a.protected(http.HandlerFunc(a.deviceSettingsGet), false, false))
	mux.Handle("PUT /api/v1/integration/device-settings", a.protected(http.HandlerFunc(a.deviceSettingsPut), false, true))
	mux.Handle("GET /api/v1/device-events", a.protected(http.HandlerFunc(a.deviceEventList), false, false))
	mux.Handle("GET /api/v1/sites", a.protected(http.HandlerFunc(a.siteList), false, false))
	mux.Handle("POST /api/v1/sites", a.protected(http.HandlerFunc(a.siteCreate), false, true))
	mux.Handle("PUT /api/v1/sites/{id}", a.protected(http.HandlerFunc(a.siteUpdate), false, true))
	mux.Handle("PUT /api/v1/sites/{id}/status", a.protected(http.HandlerFunc(a.siteStatusPut), false, true))
	mux.Handle("DELETE /api/v1/sites/{id}", a.protected(http.HandlerFunc(a.siteDelete), false, true))
	mux.Handle("GET /api/v1/policies", a.protected(http.HandlerFunc(a.policyList), false, false))
	mux.Handle("POST /api/v1/policies", a.protected(http.HandlerFunc(a.policyCreate), false, true))
	mux.Handle("PUT /api/v1/policies/{id}", a.protected(http.HandlerFunc(a.policyUpdate), false, true))
	mux.Handle("DELETE /api/v1/policies/{id}", a.protected(http.HandlerFunc(a.policyDelete), false, true))
	mux.Handle("POST /api/v1/policies/import", a.protected(http.HandlerFunc(a.policyImport), false, true))
	mux.Handle("GET /api/v1/policies/settings", a.protected(http.HandlerFunc(a.policySettingsGet), false, false))
	mux.Handle("PUT /api/v1/policies/settings", a.protected(http.HandlerFunc(a.policySettingsPut), false, true))
	mux.Handle("POST /api/v1/policies/update-now", a.protected(http.HandlerFunc(a.policyUpdateNow), false, true))
	mux.Handle("GET /api/v1/policies/recommendations", a.protected(http.HandlerFunc(a.policyRecommendations), false, false))
	mux.Handle("POST /api/v1/policies/recommendations/apply", a.protected(http.HandlerFunc(a.policyRecommendationApply), false, true))
	mux.Handle("GET /openapi/v1/status", a.openAPIOnly(http.HandlerFunc(a.openAPIStatus)))
	mux.Handle("POST /openapi/v1/ip/block", a.openAPIOnly(http.HandlerFunc(a.openAPIBlockIP)))
	mux.Handle("POST /openapi/v1/ip/unblock", a.openAPIOnly(http.HandlerFunc(a.openAPIUnblockIP)))
	mux.Handle("POST /openapi/v1/events/{format}", a.openAPIOnly(http.HandlerFunc(a.deviceEventIngest)))
	mux.Handle("/openapi/v1/", a.openAPIOnly(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, -404, "接口不存在")
	})))
	// Keep every API-prefixed request inside the API trust boundary. Unknown or
	// not-yet-implemented API routes must never be forwarded to the protected app.
	mux.Handle("/api/v1/", a.adminOnly(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, -404, "接口不存在")
	})))
	if deps.AdminHandler != nil {
		mux.Handle("GET /admin", a.adminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
		})))
		mux.Handle("GET /admin/", a.adminOnly(http.StripPrefix("/admin", deps.AdminHandler)))
	}
	mux.Handle("/", a.fallback)
	return a.recoverer(mux), nil
}

func (a *API) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logx.Error("管理 API panic", "path", r.URL.Path, "error", fmt.Sprint(recovered))
				writeError(w, http.StatusInternalServerError, -1, "系统内部错误")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (a *API) adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := iputil.GetClientIP(r, a.trusted)
		if !iputil.MatchAdminIP(clientIP, a.adminIPs) {
			writeError(w, http.StatusForbidden, -403, "无权访问")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) protected(next http.Handler, allowPasswordChange, requireCSRF bool) http.Handler {
	return a.adminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.sessions.get(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, -401, "未登录或会话已失效")
			return
		}
		if s.MustChangePassword && !allowPasswordChange {
			writeError(w, http.StatusForbidden, -403, "首次登录必须先修改密码")
			return
		}
		if requireCSRF && !constantEqual(r.Header.Get("X-CSRF-Token"), s.CSRFToken) {
			writeError(w, http.StatusForbidden, -403, "CSRF 校验失败")
			return
		}
		ctx := context.WithValue(r.Context(), sessionContextKey{}, s)
		next.ServeHTTP(w, r.WithContext(ctx))
	}))
}

func constantEqual(a, b string) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &in); err != nil || len(in.Username) < 1 || len(in.Username) > 50 || len(in.Password) < 1 || len(in.Password) > 255 {
		writeError(w, http.StatusBadRequest, -3, "用户名或密码格式错误")
		return
	}
	u, err := a.users.FindByUsername(r.Context(), in.Username)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	if u == nil || u.Status != 1 || !repository.VerifyPassword(in.Password, u.Password) {
		writeError(w, http.StatusUnauthorized, -3, "用户名或密码错误")
		return
	}
	s, err := a.sessions.create(w, u)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	clientIP := iputil.GetClientIP(r, a.trusted)
	if err := a.users.UpdateLastLogin(r.Context(), u.ID); err != nil {
		logx.Warn("更新登录时间失败", "user_id", u.ID, "err", err)
	}
	if err := a.loginLogs.Insert(r.Context(), u.ID, clientIP); err != nil {
		logx.Warn("写入登录日志失败", "user_id", u.ID, "err", err)
	}
	writeOK(w, "登录成功", map[string]any{
		"user_id": u.ID, "username": u.Username, "role": "admin",
		"csrf_token": s.CSRFToken, "must_change_password": s.MustChangePassword,
	})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	a.sessions.delete(w, r)
	writeOK(w, "已登出", nil)
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	writeOK(w, "success", map[string]any{"user_id": s.UserID, "username": s.Username, "role": "admin", "csrf_token": s.CSRFToken, "must_change_password": s.MustChangePassword})
}

func (a *API) dashboardStats(w http.ResponseWriter, r *http.Request) {
	total, err := a.accessLogs.TodayCount(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	ips, err := a.accessLogs.TodayDistinctIPCount(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	blocked, err := a.attacks.TodaySumAttackCount(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	blacklist, err := a.ipList.CountBlacklist(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	whitelist, err := a.ipList.CountByType(r.Context(), model.IPTypeWhitelist)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "success", map[string]any{"total_requests": total, "total_ips": ips, "blocked_requests": blocked, "blacklist_ips": blacklist, "whitelist_ips": whitelist})
}

func (a *API) dashboardTrend(w http.ResponseWriter, r *http.Request) {
	trend, err := a.attacks.TodayHourlyTrend(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	if trend == nil {
		trend = []map[string]any{}
	}
	writeOK(w, "success", map[string]any{"trend": trend})
}

func (a *API) dashboardTopIPs(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 10, 1, 50)
	list, err := a.attacks.TodayTopAttackIPs(r.Context(), limit)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	if list == nil {
		list = []map[string]any{}
	}
	writeOK(w, "success", list)
}

func (a *API) attackList(w http.ResponseWriter, r *http.Request) {
	page, size := pagination(r)
	filter, err := attackFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, -3, err.Error())
		return
	}
	list, total, err := a.attacks.List(r.Context(), filter, page, size)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	if list == nil {
		list = []*model.AttackLog{}
	}
	writeOK(w, "success", pageData(list, total, page, size))
}

func attackFilter(r *http.Request) (repository.AttackLogFilter, error) {
	filter := repository.AttackLogFilter{
		EventID:    strings.TrimSpace(r.URL.Query().Get("event_id")),
		AttackType: strings.TrimSpace(r.URL.Query().Get("attack_type")),
		IP:         strings.TrimSpace(r.URL.Query().Get("ip")),
	}
	if filter.EventID != "" && !validEventID(filter.EventID) {
		return filter, errors.New("事件编号格式非法")
	}
	if value := r.URL.Query().Get("severity"); value != "" {
		severity, err := strconv.Atoi(value)
		if err != nil || severity < model.AttackSeverityInfo || severity > model.AttackSeverityCritical {
			return filter, errors.New("严重度必须为 1-5")
		}
		filter.Severity = severity
	}
	parseTime := func(key string) (*time.Time, error) {
		value := r.URL.Query().Get(key)
		if value == "" {
			return nil, nil
		}
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return nil, fmt.Errorf("%s 必须为 RFC3339 时间", key)
		}
		return &parsed, nil
	}
	var err error
	if filter.StartAt, err = parseTime("start_at"); err != nil {
		return filter, err
	}
	if filter.EndAt, err = parseTime("end_at"); err != nil {
		return filter, err
	}
	if filter.StartAt != nil && filter.EndAt != nil && !filter.EndAt.After(*filter.StartAt) {
		return filter, errors.New("end_at 必须晚于 start_at")
	}
	return filter, nil
}

func validEventID(value string) bool {
	if len(value) < 8 || len(value) > 40 || !strings.HasPrefix(value, "JS-") {
		return false
	}
	for _, char := range value {
		if (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}

func (a *API) attackExport(w http.ResponseWriter, r *http.Request) {
	filter, err := attackFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, -3, err.Error())
		return
	}
	filename := "jingshield-attacks-" + time.Now().Format("20060102-150405") + ".csv"
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.WriteString(w, "\uFEFF")
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{"记录ID", "事件编号", "严重度", "攻击类型", "来源IP", "归属地", "访问域名", "方法", "URI", "攻击详情", "请求报文", "累计次数", "处置结果", "发生时间"}); err != nil {
		return
	}
	err = a.attacks.Stream(r.Context(), filter, func(log *model.AttackLog) error {
		status := "已拦截"
		if log.Status == 2 {
			status = "仅记录"
		}
		return writer.Write([]string{
			strconv.FormatInt(log.ID, 10), safeSpreadsheetCell(log.EventID), model.AttackSeverityLabel(log.Severity), safeSpreadsheetCell(log.AttackType),
			safeSpreadsheetCell(log.IP), safeSpreadsheetCell(log.IPLocation), safeSpreadsheetCell(log.Host),
			safeSpreadsheetCell(log.Method), safeSpreadsheetCell(log.URI), safeSpreadsheetCell(log.AttackDetail),
			safeSpreadsheetCell(log.RequestPacket),
			strconv.Itoa(log.AttackCount), status, log.CreatedAt.Format(time.RFC3339),
		})
	})
	writer.Flush()
	if err == nil {
		err = writer.Error()
	}
	if err != nil {
		logx.Error("导出攻击事件失败", "err", err)
	}
}

func safeSpreadsheetCell(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}

func (a *API) accessLogList(w http.ResponseWriter, r *http.Request) {
	page, size := pagination(r)
	list, total, err := a.accessLogs.List(r.Context(), r.URL.Query().Get("ip"), page, size)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	if list == nil {
		list = []*model.AccessLog{}
	}
	writeOK(w, "success", pageData(list, total, page, size))
}

func (a *API) loginLogList(w http.ResponseWriter, r *http.Request) {
	page, size := pagination(r)
	list, total, err := a.loginLogs.List(r.Context(), page, size)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	if list == nil {
		list = []*model.LoginLog{}
	}
	writeOK(w, "success", pageData(list, total, page, size))
}

func (a *API) ipListGet(w http.ResponseWriter, r *http.Request) {
	page, size := pagination(r)
	typ := queryInt(r, "type", 0, 0, 3)
	list, total, err := a.ipList.ListByType(r.Context(), typ, r.URL.Query().Get("ip"), page, size)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	if list == nil {
		list = []*model.IPList{}
	}
	writeOK(w, "success", pageData(list, total, page, size))
}

func (a *API) ipListAdd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IP            string `json:"ip"`
		Type          int    `json:"type"`
		Reason        string `json:"reason"`
		ExpireSeconds int    `json:"expire_seconds"`
	}
	if err := decodeJSON(w, r, &in); err != nil || !validIPRule(in.IP) || in.Type < 1 || in.Type > 3 || len(in.Reason) > 255 {
		writeError(w, http.StatusBadRequest, -3, "IP 名单参数非法")
		return
	}
	var expires *time.Time
	if in.Type == model.IPTypeTempBlacklist {
		if in.ExpireSeconds <= 0 || in.ExpireSeconds > 31536000 {
			writeError(w, http.StatusBadRequest, -3, "临时黑名单有效期必须为 1 到 31536000 秒")
			return
		}
		t := time.Now().Add(time.Duration(in.ExpireSeconds) * time.Second)
		expires = &t
	}
	if err := a.ipList.Add(r.Context(), strings.TrimSpace(in.IP), in.Type, in.Reason, expires); err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "新增成功", nil)
}

func (a *API) ipListDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, -3, "ID 非法")
		return
	}
	if err := a.ipList.Delete(r.Context(), id); err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "删除成功", nil)
}

func (a *API) configGet(w http.ResponseWriter, r *http.Request) {
	list, err := a.configs.ListAll(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	for _, item := range list {
		if item.ConfigKey == "api_key" && item.ConfigValue != "" {
			item.ConfigValue = "********"
		}
	}
	if list == nil {
		list = []*model.Config{}
	}
	writeOK(w, "success", list)
}

func (a *API) configPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ConfigKey   string `json:"config_key"`
		ConfigValue string `json:"config_value"`
	}
	if err := decodeJSON(w, r, &in); err != nil || !validDynamicConfig(in.ConfigKey, in.ConfigValue) {
		writeError(w, http.StatusBadRequest, -3, "配置键或配置值非法")
		return
	}
	if err := a.dynamic.Set(r.Context(), in.ConfigKey, in.ConfigValue); err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "配置已更新", nil)
}

var statusKeys = []string{"system_status", "cc_protection_status", "xss_protection_status", "sql_protection_status", "path_traversal_protection_status", "ssrf_protection_status", "xxe_protection_status", "oversea_ip_status", "file_check_status"}

func (a *API) systemStatusGet(w http.ResponseWriter, _ *http.Request) {
	data := make(map[string]int, len(statusKeys))
	for _, key := range statusKeys {
		data[key] = a.dynamic.GetInt(key)
	}
	writeOK(w, "success", data)
}

func (a *API) systemStatusPut(w http.ResponseWriter, r *http.Request) {
	values := map[string]int{}
	if err := decodeJSON(w, r, &values); err != nil || len(values) == 0 {
		writeError(w, http.StatusBadRequest, -3, "至少提供一个状态字段")
		return
	}
	allowed := make(map[string]bool, len(statusKeys))
	for _, key := range statusKeys {
		allowed[key] = true
	}
	for key, value := range values {
		if !allowed[key] || (value != 0 && value != 1) {
			writeError(w, http.StatusBadRequest, -3, "状态字段或取值非法")
			return
		}
	}
	for key, value := range values {
		if err := a.dynamic.Set(r.Context(), key, strconv.Itoa(value)); err != nil {
			a.internalError(w, r, err)
			return
		}
	}
	writeOK(w, "系统状态已更新", nil)
}

func (a *API) cacheDelete(w http.ResponseWriter, r *http.Request) {
	if err := a.state.ClearAll(r.Context()); err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "缓存已清理", nil)
}

func (a *API) passwordPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(w, r, &in); err != nil || len(in.OldPassword) < 1 || len(in.OldPassword) > 255 || len(in.NewPassword) < 12 || len(in.NewPassword) > 255 || in.OldPassword == in.NewPassword {
		writeError(w, http.StatusBadRequest, -3, "新密码须为 12-255 字符且不能与旧密码相同")
		return
	}
	s := currentSession(r)
	u, err := a.users.FindByID(r.Context(), s.UserID)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	if u == nil || u.Status != 1 || !repository.VerifyPassword(in.OldPassword, u.Password) {
		writeError(w, http.StatusBadRequest, -3, "旧密码错误")
		return
	}
	hash, err := repository.HashPassword(in.NewPassword)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	if err := a.users.UpdatePassword(r.Context(), u.ID, hash); err != nil {
		a.internalError(w, r, err)
		return
	}
	a.sessions.delete(w, r)
	writeOK(w, "密码修改成功，请重新登录", nil)
}

func currentSession(r *http.Request) session { return r.Context().Value(sessionContextKey{}).(session) }

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	return decodeJSONLimit(w, r, dst, maxJSONBody)
}

func decodeJSONLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("请求体只能包含一个 JSON 值")
	}
	return nil
}

type envelope struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

func writeOK(w http.ResponseWriter, message string, data any) {
	writeJSON(w, http.StatusOK, envelope{Code: 0, Message: message, Data: data})
}
func writeError(w http.ResponseWriter, status, code int, message string) {
	writeJSON(w, status, envelope{Code: code, Message: message, Data: nil})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (a *API) internalError(w http.ResponseWriter, r *http.Request, err error) {
	logx.Error("管理 API 请求失败", "method", r.Method, "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, -1, "系统内部错误")
}

func pagination(r *http.Request) (int, int) {
	return queryInt(r, "page", 1, 1, 1_000_000), queryInt(r, "size", 10, 1, 100)
}
func queryInt(r *http.Request, key string, fallback, min, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil || n < min || n > max {
		return fallback
	}
	return n
}
func pageData(list any, total int64, page, size int) map[string]any {
	return map[string]any{"list": list, "total": total, "page": page, "size": size}
}

func validIPRule(rule string) bool {
	rule = strings.TrimSpace(rule)
	if net.ParseIP(rule) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(rule); err == nil {
		return true
	}
	parts := strings.Split(rule, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "*" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return strings.Contains(rule, "*")
}

func validDynamicConfig(key, value string) bool {
	boolKeys := map[string]bool{"system_status": true, "cc_protection_status": true, "xss_protection_status": true, "sql_protection_status": true, "path_traversal_protection_status": true, "ssrf_protection_status": true, "xxe_protection_status": true, "file_check_status": true, "oversea_ip_status": true, "api_enabled": true}
	if boolKeys[key] {
		return value == "0" || value == "1"
	}
	limits := map[string][2]int{"cc_visit_count": {1, 1_000_000}, "cc_visit_time": {1, 86400}, "cc_blacklist_time": {1, 31536000}, "cc_verify_fail_limit": {1, 1000}, "cc_whitelist_time": {1, 31536000}, "cc_verification_mode": {1, 8}, "log_keep_days": {1, 3650}}
	limits["alert_cpu_percent"] = [2]int{1, 100}
	limits["alert_memory_percent"] = [2]int{1, 100}
	limits["alert_disk_percent"] = [2]int{1, 100}
	limits["alert_log_size_mb"] = [2]int{1, 1_048_576}
	limits["alert_request_rate"] = [2]int{1, 1_000_000}
	if limit, ok := limits[key]; ok {
		n, err := strconv.Atoi(value)
		return err == nil && n >= limit[0] && n <= limit[1]
	}
	if key == "error_output_format" {
		return value == "json" || value == "html"
	}
	if key == "custom_error_page" {
		return len(value) <= 65535
	}
	if key == "security_contact" {
		trimmed := strings.TrimSpace(value)
		return len(trimmed) >= 1 && len(trimmed) <= 200 && !strings.ContainsAny(trimmed, "\r\n")
	}
	return false
}
