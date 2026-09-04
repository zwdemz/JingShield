package api

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"jingshield/internal/model"
	"jingshield/internal/pkg/iputil"
)

const maxDeviceEventBody = 1 << 20

type normalizedDeviceEvent struct {
	DeviceName string
	Vendor     string
	EventType  string
	Severity   int
	EventIP    string
	Message    string
}

func (a *API) deviceEventIngest(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(r.PathValue("format"))
	if !map[string]bool{"json": true, "cef": true, "leef": true, "suricata": true, "wazuh": true}[format] {
		writeError(w, http.StatusNotFound, -404, "不支持的设备事件格式")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDeviceEventBody))
	if err != nil {
		writeError(w, http.StatusBadRequest, -3, "设备事件超过 1MB 或无法读取")
		return
	}
	event, err := parseDeviceEvent(format, body)
	if err != nil {
		writeError(w, http.StatusBadRequest, -3, err.Error())
		return
	}
	dbEvent := &model.DeviceEvent{DeviceName: event.DeviceName, Vendor: event.Vendor, Format: format, SourceIP: iputil.GetClientIP(r, a.trusted), EventType: event.EventType, Severity: event.Severity, EventIP: event.EventIP, Message: event.Message, RawJSON: truncateEventRaw(string(body)), ActionTaken: "recorded"}
	if a.dynamic.GetBool("device_auto_block_enabled") && event.Severity >= a.dynamic.GetIntDefault("device_auto_block_severity", 8) && net.ParseIP(event.EventIP) != nil {
		seconds := a.dynamic.GetIntDefault("device_auto_block_seconds", 3600)
		_, _ = a.ipList.DeleteByIP(r.Context(), event.EventIP)
		expires := time.Now().Add(time.Duration(seconds) * time.Second)
		if err := a.ipList.Add(r.Context(), event.EventIP, model.IPTypeTempBlacklist, "设备联动: "+event.Vendor+" / "+event.Message, &expires); err != nil {
			a.internalError(w, r, err)
			return
		}
		dbEvent.ActionTaken = "temporary_block"
	}
	if err := a.deviceEvents.Insert(r.Context(), dbEvent); err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "安全设备事件已归一化", map[string]any{"event_id": dbEvent.ID, "vendor": dbEvent.Vendor, "format": format, "event_type": dbEvent.EventType, "severity": dbEvent.Severity, "event_ip": dbEvent.EventIP, "action_taken": dbEvent.ActionTaken})
}

func (a *API) deviceEventList(w http.ResponseWriter, r *http.Request) {
	page, size := pagination(r)
	list, total, err := a.deviceEvents.List(r.Context(), r.URL.Query().Get("vendor"), page, size)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "success", pageData(list, total, page, size))
}

func (a *API) deviceSettingsGet(w http.ResponseWriter, _ *http.Request) {
	writeOK(w, "success", map[string]any{"auto_block_enabled": a.dynamic.GetBool("device_auto_block_enabled"), "auto_block_severity": a.dynamic.GetIntDefault("device_auto_block_severity", 8), "auto_block_seconds": a.dynamic.GetIntDefault("device_auto_block_seconds", 3600)})
}

func (a *API) deviceSettingsPut(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AutoBlockEnabled  bool `json:"auto_block_enabled"`
		AutoBlockSeverity int  `json:"auto_block_severity"`
		AutoBlockSeconds  int  `json:"auto_block_seconds"`
	}
	if decodeJSON(w, r, &input) != nil || input.AutoBlockSeverity < 1 || input.AutoBlockSeverity > 10 || input.AutoBlockSeconds < 60 || input.AutoBlockSeconds > 31536000 {
		writeError(w, http.StatusBadRequest, -3, "设备联动参数非法")
		return
	}
	values := map[string]string{"device_auto_block_enabled": boolString(input.AutoBlockEnabled), "device_auto_block_severity": strconv.Itoa(input.AutoBlockSeverity), "device_auto_block_seconds": strconv.Itoa(input.AutoBlockSeconds)}
	for key, value := range values {
		if err := a.dynamic.Set(r.Context(), key, value); err != nil {
			a.internalError(w, r, err)
			return
		}
	}
	writeOK(w, "安全设备联动策略已更新", nil)
}

func parseDeviceEvent(format string, body []byte) (normalizedDeviceEvent, error) {
	switch format {
	case "cef":
		return parseCEF(strings.TrimSpace(string(body)))
	case "leef":
		return parseLEEF(strings.TrimSpace(string(body)))
	case "suricata":
		return parseSuricata(body)
	case "wazuh":
		return parseWazuh(body)
	default:
		return parseGenericJSON(body)
	}
}

func parseGenericJSON(body []byte) (normalizedDeviceEvent, error) {
	var value struct {
		DeviceName string `json:"device_name"`
		Vendor     string `json:"vendor"`
		EventType  string `json:"event_type"`
		Severity   int    `json:"severity"`
		EventIP    string `json:"event_ip"`
		SourceIP   string `json:"source_ip"`
		SrcIP      string `json:"src_ip"`
		Message    string `json:"message"`
	}
	if json.Unmarshal(body, &value) != nil {
		return normalizedDeviceEvent{}, errors.New("通用 JSON 事件格式非法")
	}
	ip := firstNonEmpty(value.EventIP, value.SourceIP, value.SrcIP)
	return normalizeEvent(value.DeviceName, value.Vendor, value.EventType, value.Severity, ip, value.Message)
}

func parseSuricata(body []byte) (normalizedDeviceEvent, error) {
	var value struct {
		SrcIP     string `json:"src_ip"`
		EventType string `json:"event_type"`
		Hostname  string `json:"host"`
		Alert     struct {
			Signature string `json:"signature"`
			Category  string `json:"category"`
			Severity  int    `json:"severity"`
		} `json:"alert"`
	}
	if json.Unmarshal(body, &value) != nil {
		return normalizedDeviceEvent{}, errors.New("Suricata EVE JSON 格式非法")
	}
	severity := 11 - value.Alert.Severity*2
	if severity < 1 {
		severity = 1
	}
	if severity > 10 {
		severity = 10
	}
	return normalizeEvent(firstNonEmpty(value.Hostname, "Suricata"), "Suricata", firstNonEmpty(value.Alert.Category, value.EventType), severity, value.SrcIP, value.Alert.Signature)
}

func parseWazuh(body []byte) (normalizedDeviceEvent, error) {
	var value struct {
		Agent struct {
			Name string `json:"name"`
		} `json:"agent"`
		Rule struct {
			Level       int      `json:"level"`
			Description string   `json:"description"`
			Groups      []string `json:"groups"`
		} `json:"rule"`
		Data struct {
			SrcIP    string `json:"srcip"`
			SrcIPAlt string `json:"src_ip"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &value) != nil {
		return normalizedDeviceEvent{}, errors.New("Wazuh JSON 格式非法")
	}
	severity := value.Rule.Level
	if severity > 10 {
		severity = 10
	}
	return normalizeEvent(firstNonEmpty(value.Agent.Name, "Wazuh"), "Wazuh", strings.Join(value.Rule.Groups, ","), severity, firstNonEmpty(value.Data.SrcIP, value.Data.SrcIPAlt), value.Rule.Description)
}

func parseCEF(line string) (normalizedDeviceEvent, error) {
	if !strings.HasPrefix(line, "CEF:") {
		return normalizedDeviceEvent{}, errors.New("CEF 事件必须以 CEF: 开头")
	}
	parts := splitEscaped(line, '|', 8)
	if len(parts) < 8 {
		return normalizedDeviceEvent{}, errors.New("CEF 事件字段不足")
	}
	ext := parseKeyValues(parts[7], ' ')
	severity, _ := strconv.Atoi(parts[6])
	if severity == 0 {
		severity, _ = strconv.Atoi(ext["sev"])
	}
	return normalizeEvent(firstNonEmpty(ext["dvchost"], parts[2]), parts[1], firstNonEmpty(parts[5], parts[4]), severity, firstNonEmpty(ext["src"], ext["sourceAddress"]), firstNonEmpty(ext["msg"], parts[5]))
}

func parseLEEF(line string) (normalizedDeviceEvent, error) {
	if !strings.HasPrefix(line, "LEEF:") {
		return normalizedDeviceEvent{}, errors.New("LEEF 事件必须以 LEEF: 开头")
	}
	parts := splitEscaped(line, '|', 6)
	if len(parts) < 6 {
		return normalizedDeviceEvent{}, errors.New("LEEF 事件字段不足")
	}
	ext := parseKeyValues(parts[5], '\t')
	severity, _ := strconv.Atoi(firstNonEmpty(ext["sev"], ext["severity"]))
	return normalizeEvent(firstNonEmpty(ext["devName"], parts[2]), parts[1], parts[4], severity, firstNonEmpty(ext["src"], ext["srcIP"]), firstNonEmpty(ext["msg"], parts[4]))
}

func normalizeEvent(device, vendor, eventType string, severity int, eventIP, message string) (normalizedDeviceEvent, error) {
	device, vendor, eventType, eventIP, message = strings.TrimSpace(device), strings.TrimSpace(vendor), strings.TrimSpace(eventType), strings.TrimSpace(eventIP), strings.TrimSpace(message)
	if device == "" {
		device = "unknown"
	}
	if vendor == "" {
		vendor = "generic"
	}
	if eventType == "" {
		eventType = "security_event"
	}
	if severity < 1 {
		severity = 1
	}
	if severity > 10 {
		severity = 10
	}
	if len(device) > 100 || len(vendor) > 50 || len(eventType) > 100 || len(message) > 500 || (eventIP != "" && net.ParseIP(eventIP) == nil) {
		return normalizedDeviceEvent{}, errors.New("设备事件字段长度、严重度或事件 IP 非法")
	}
	return normalizedDeviceEvent{DeviceName: device, Vendor: vendor, EventType: eventType, Severity: severity, EventIP: eventIP, Message: message}, nil
}

func splitEscaped(value string, delimiter rune, limit int) []string {
	parts, current, escaped := []string{}, strings.Builder{}, false
	for _, char := range value {
		if escaped {
			current.WriteRune(char)
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if char == delimiter && len(parts) < limit-1 {
			parts = append(parts, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(char)
	}
	parts = append(parts, current.String())
	return parts
}
func parseKeyValues(value string, separator rune) map[string]string {
	result := map[string]string{}
	if separator == ' ' {
		// CEF extension values may contain spaces. Locate the next key= token
		// instead of splitting every word so msg= remains intact.
		matches := regexp.MustCompile(`(?:^|\s)([A-Za-z0-9_.-]+)=`).FindAllStringSubmatchIndex(value, -1)
		for index, match := range matches {
			start := match[1]
			end := len(value)
			if index+1 < len(matches) {
				end = matches[index+1][0]
			}
			result[value[match[2]:match[3]]] = strings.TrimSpace(value[start:end])
		}
		return result
	}
	for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == separator }) {
		pair := strings.SplitN(field, "=", 2)
		if len(pair) == 2 {
			result[pair[0]] = pair[1]
		}
	}
	return result
}
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
func truncateEventRaw(value string) string {
	if len(value) <= 65535 {
		return value
	}
	return value[:65535]
}
