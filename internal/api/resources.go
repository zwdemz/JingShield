package api

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

type resourceAlert struct {
	Resource  string  `json:"resource"`
	Level     string  `json:"level"`
	Message   string  `json:"message"`
	Current   float64 `json:"current"`
	Threshold float64 `json:"threshold"`
	Unit      string  `json:"unit"`
}

var alertThresholdLimits = map[string][2]int{
	"cpu_percent": {1, 100}, "memory_percent": {1, 100}, "disk_percent": {1, 100},
	"log_size_mb": {1, 1_048_576}, "request_rate": {1, 1_000_000},
}

func (a *API) systemResourcesGet(w http.ResponseWriter, r *http.Request) {
	cpuValues, err := cpu.Percent(0, false)
	if err != nil || len(cpuValues) == 0 {
		if err == nil {
			err = os.ErrInvalid
		}
		a.internalError(w, r, err)
		return
	}
	memory, err := mem.VirtualMemory()
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	logDir := a.logDir
	if logDir == "" {
		logDir = "."
	}
	absLogDir, err := filepath.Abs(logDir)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	diskPath := absLogDir
	if _, err := os.Stat(diskPath); err != nil {
		diskPath = filepath.VolumeName(absLogDir) + string(filepath.Separator)
		if diskPath == "" {
			diskPath = "."
		}
	}
	diskUsage, err := disk.Usage(diskPath)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	hostInfo, err := host.Info()
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	logBytes, err := directorySize(absLogDir)
	if err != nil && !os.IsNotExist(err) {
		a.internalError(w, r, err)
		return
	}
	requestRate, err := a.accessLogs.CountLastMinute(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	thresholds := map[string]int{
		"cpu_percent":    a.dynamic.GetIntDefault("alert_cpu_percent", 80),
		"memory_percent": a.dynamic.GetIntDefault("alert_memory_percent", 85),
		"disk_percent":   a.dynamic.GetIntDefault("alert_disk_percent", 85),
		"log_size_mb":    a.dynamic.GetIntDefault("alert_log_size_mb", 512),
		"request_rate":   a.dynamic.GetIntDefault("alert_request_rate", 600),
	}
	logMB := float64(logBytes) / 1024 / 1024
	metrics := map[string]float64{"cpu": cpuValues[0], "memory": memory.UsedPercent, "disk": diskUsage.UsedPercent, "log": logMB, "rate": float64(requestRate)}
	alerts := make([]resourceAlert, 0)
	checks := []struct {
		resource, message, unit, threshold string
		value                              float64
	}{
		{"cpu", "CPU 使用率超过阈值", "%", "cpu_percent", metrics["cpu"]},
		{"memory", "内存使用率超过阈值", "%", "memory_percent", metrics["memory"]},
		{"disk", "日志所在磁盘使用率超过阈值", "%", "disk_percent", metrics["disk"]},
		{"log", "日志目录占用超过阈值", "MB", "log_size_mb", metrics["log"]},
		{"rate", "业务请求速率超过阈值", "请求/分钟", "request_rate", metrics["rate"]},
	}
	for _, check := range checks {
		threshold := float64(thresholds[check.threshold])
		if check.value >= threshold {
			level := "warning"
			if check.value >= threshold*1.2 {
				level = "critical"
			}
			alerts = append(alerts, resourceAlert{Resource: check.resource, Level: level, Message: check.message, Current: check.value, Threshold: threshold, Unit: check.unit})
		}
	}
	writeOK(w, "success", map[string]any{
		"hostname": hostInfo.Hostname, "os": hostInfo.OS, "platform": hostInfo.Platform, "uptime_seconds": hostInfo.Uptime,
		"cpu_percent": metrics["cpu"], "memory_used_bytes": memory.Used, "memory_total_bytes": memory.Total, "memory_percent": metrics["memory"],
		"disk_used_bytes": diskUsage.Used, "disk_total_bytes": diskUsage.Total, "disk_percent": metrics["disk"],
		"log_size_bytes": logBytes, "request_rate": requestRate, "thresholds": thresholds, "alerts": alerts,
	})
}

func (a *API) alertThresholdsPut(w http.ResponseWriter, r *http.Request) {
	values := map[string]int{}
	if decodeJSON(w, r, &values) != nil || len(values) == 0 {
		writeError(w, http.StatusBadRequest, -3, "至少提供一个告警阈值")
		return
	}
	for key, value := range values {
		limit, ok := alertThresholdLimits[key]
		if !ok || value < limit[0] || value > limit[1] {
			writeError(w, http.StatusBadRequest, -3, "告警阈值字段或取值非法")
			return
		}
	}
	for key, value := range values {
		if err := a.dynamic.Set(r.Context(), "alert_"+key, strconv.Itoa(value)); err != nil {
			a.internalError(w, r, err)
			return
		}
	}
	writeOK(w, "资源告警阈值已更新", nil)
}

func directorySize(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	return total, err
}
