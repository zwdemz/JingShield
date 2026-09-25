package api

import (
	"errors"
	"jingshield/internal/config"
	"jingshield/internal/pkg/logx"
	"net/http"
	"time"
)

type protectionSettingsInput struct {
	Profile string            `json:"profile"`
	Values  map[string]string `json:"values"`
}

func protectionChanges(input protectionSettingsInput) (map[string]string, error) {
	values := map[string]string{}
	if input.Profile != "" {
		for _, profile := range config.ProtectionProfiles() {
			if profile.ID == input.Profile {
				values = profile.Values
				break
			}
		}
		if len(values) == 0 {
			return nil, errors.New("防护等级非法")
		}
	}
	for key, value := range input.Values {
		if !config.ValidProtectionValue(key, value) {
			return nil, errors.New("引擎设置或行为参数非法")
		}
		values[key] = value
	}
	if len(values) == 0 {
		return nil, errors.New("至少提供一个引擎设置或防护等级")
	}
	return values, nil
}

func (a *API) protectionSettingsGet(w http.ResponseWriter, _ *http.Request) {
	writeOK(w, "success", config.ProtectionSnapshot(a.dynamic.All()))
}

func (a *API) protectionSettingsPut(w http.ResponseWriter, r *http.Request) {
	var input protectionSettingsInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, 400, -3, "防护设置格式非法")
		return
	}
	values, err := protectionChanges(input)
	if err != nil {
		writeError(w, 400, -3, err.Error())
		return
	}
	if err := a.dynamic.SetMany(r.Context(), values); err != nil {
		a.internalError(w, r, err)
		return
	}
	logx.Info("防护设置已更新", "user_id", currentSession(r).UserID, "profile", input.Profile, "changed_fields", len(values))
	writeOK(w, "防护设置已原子应用", config.ProtectionSnapshot(a.dynamic.All()))
}

func (a *API) wafStatusGet(w http.ResponseWriter, r *http.Request) {
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
	metrics := map[string]any{}
	if a.wafMetrics != nil {
		metrics = a.wafMetrics()
	}
	values := a.dynamic.All()
	writeOK(w, "success", map[string]any{
		"waf_enabled": values["system_status"] == "1", "started_at": a.startedAt.UTC().Format(time.RFC3339),
		"uptime_seconds": int64(time.Since(a.startedAt).Seconds()), "state_backend": a.stateBackend, "shared_state": a.stateBackend == "redis",
		"metrics": metrics, "protection": config.ProtectionSnapshot(values), "sites": map[string]int{"total": len(sites), "enabled": enabled},
		"server_time": time.Now().UTC().Format(time.RFC3339),
	})
}
