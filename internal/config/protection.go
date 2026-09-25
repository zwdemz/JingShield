package config

import "strconv"

// EngineSetting names an implemented engine; Enabled is its configured state,
// not an assertion that the master switch or a dependent resource is healthy.
type EngineSetting struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Enabled bool   `json:"enabled"`
}

// ProtectionProfile is an explicit, reproducible set of engine settings.
type ProtectionProfile struct {
	ID          string            `json:"id"`
	Label       string            `json:"label"`
	Description string            `json:"description"`
	Values      map[string]string `json:"values"`
}

var engineDefinitions = []EngineSetting{
	{Key: "cc_protection_status", Label: "CC 频率防护"},
	{Key: "xss_protection_status", Label: "XSS 防护"},
	{Key: "sql_protection_status", Label: "SQL 注入防护"},
	{Key: "path_traversal_protection_status", Label: "路径穿越防护"},
	{Key: "ssrf_protection_status", Label: "SSRF 防护"},
	{Key: "xxe_protection_status", Label: "XXE 防护"},
	{Key: "scanner_protection_status", Label: "行为扫描防护"},
	{Key: "policy_protection_status", Label: "自定义策略引擎"},
}

// ProtectionProfiles returns independent profile copies, excluding the master
// switch, geographic blocking and features without a runtime implementation.
func ProtectionProfiles() []ProtectionProfile {
	profiles := []ProtectionProfile{
		{ID: "low", Label: "兼容优先", Description: "保留语义检测，放宽频率阈值，行为扫描仅观察。", Values: map[string]string{"cc_visit_count": "300", "cc_visit_time": "60", "behavior_window_seconds": "300", "behavior_threshold": "16", "behavior_block_seconds": "300", "behavior_mode": "observe"}},
		{ID: "standard", Label: "标准防护", Description: "语义检测与行为拦截同时启用，适合日常运行。", Values: map[string]string{"cc_visit_count": "100", "cc_visit_time": "60", "behavior_window_seconds": "300", "behavior_threshold": "8", "behavior_block_seconds": "600", "behavior_mode": "block"}},
		{ID: "strict", Label: "严格防护", Description: "降低频率和行为触发阈值；启用前评估 NAS 并发业务。", Values: map[string]string{"cc_visit_count": "60", "cc_visit_time": "60", "behavior_window_seconds": "300", "behavior_threshold": "4", "behavior_block_seconds": "1800", "behavior_mode": "block"}},
	}
	for _, profile := range profiles {
		for _, engine := range engineDefinitions {
			profile.Values[engine.Key] = "1"
		}
	}
	return profiles
}

// ProtectionDefaults supplies defaults for missing database rows without
// overriding the administrator's existing persisted values.
func ProtectionDefaults() map[string]string { return ProtectionProfiles()[1].Values }

// ProtectionSnapshot derives the effective profile from a single configuration
// snapshot. Any independent override is shown as custom rather than stale preset.
func ProtectionSnapshot(values map[string]string) map[string]any {
	current := ProtectionDefaults()
	for key := range current {
		if value, ok := values[key]; ok {
			current[key] = value
		}
	}
	current["system_status"] = "1"
	if value, ok := values["system_status"]; ok {
		current["system_status"] = value
	}
	profileID := "custom"
	profiles := ProtectionProfiles()
	for _, profile := range profiles {
		matches := true
		for key, value := range profile.Values {
			if current[key] != value {
				matches = false
				break
			}
		}
		if matches {
			profileID = profile.ID
			break
		}
	}
	engines := append([]EngineSetting(nil), engineDefinitions...)
	for i := range engines {
		engines[i].Enabled = current[engines[i].Key] == "1"
	}
	return map[string]any{"profile": profileID, "profiles": profiles, "values": current, "engines": engines}
}

// ValidProtectionValue validates implemented engine controls and bounded
// behavior parameters. Unknown keys never become writable through this API.
func ValidProtectionValue(key, value string) bool {
	if key == "system_status" {
		return value == "0" || value == "1"
	}
	for _, engine := range engineDefinitions {
		if key == engine.Key {
			return value == "0" || value == "1"
		}
	}
	if key == "behavior_mode" {
		return value == "observe" || value == "block"
	}
	limits := map[string][2]int{"behavior_window_seconds": {10, 3600}, "behavior_threshold": {2, 1000}, "behavior_block_seconds": {10, 86400}, "cc_visit_count": {1, 1000000}, "cc_visit_time": {1, 86400}}
	limit, ok := limits[key]
	if !ok {
		return false
	}
	number, err := strconv.Atoi(value)
	return err == nil && number >= limit[0] && number <= limit[1]
}
