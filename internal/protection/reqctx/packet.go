package reqctx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	maxStoredRequestPacket = 32 * 1024
	maxStoredRequestBody   = 16 * 1024
	redactedValue          = "[REDACTED]"
)

// SanitizedRequestPacket returns an operator-readable HTTP request snapshot.
// Credentials are redacted and large bodies are truncated before persistence.
func (rc *RequestContext) SanitizedRequestPacket() string {
	if rc == nil || rc.R == nil {
		return ""
	}
	proto := rc.R.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	var packet strings.Builder
	fmt.Fprintf(&packet, "%s %s %s\n", cleanPacketText(rc.Method), sanitizedRequestURI(rc.URI), cleanPacketText(proto))
	if rc.R.Host != "" {
		fmt.Fprintf(&packet, "Host: %s\n", cleanPacketText(rc.R.Host))
	}
	keys := make([]string, 0, len(rc.Header))
	for key := range rc.Header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := strings.Join(rc.Header.Values(key), ", ")
		if sensitiveHeader(key) {
			value = redactedValue
		}
		fmt.Fprintf(&packet, "%s: %s\n", cleanPacketText(key), cleanPacketText(value))
	}
	if len(rc.RawBody) > 0 {
		packet.WriteByte('\n')
		packet.WriteString(sanitizedRequestBody(rc))
	}
	return truncatePacket(packet.String(), maxStoredRequestPacket)
}

func sanitizedRequestURI(raw string) string {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return cleanPacketText(truncatePacket(redactTextSecrets(raw), 4096))
	}
	query := parsed.Query()
	for key := range query {
		if sensitiveField(key) {
			query[key] = []string{redactedValue}
		}
	}
	parsed.RawQuery = query.Encode()
	return cleanPacketText(truncatePacket(parsed.RequestURI(), 4096))
}

func sanitizedRequestBody(rc *RequestContext) string {
	mediaType, _, _ := mime.ParseMediaType(rc.Header.Get("Content-Type"))
	switch mediaType {
	case "application/json":
		decoder := json.NewDecoder(bytes.NewReader(rc.RawBody))
		decoder.UseNumber()
		var value any
		if decoder.Decode(&value) == nil {
			redactJSONValue(value)
			if encoded, err := json.MarshalIndent(value, "", "  "); err == nil {
				return truncatePacket(string(encoded), maxStoredRequestBody)
			}
		}
	case "application/x-www-form-urlencoded":
		if values, err := url.ParseQuery(string(rc.RawBody)); err == nil {
			for key := range values {
				if sensitiveField(key) {
					values[key] = []string{redactedValue}
				}
			}
			return truncatePacket(values.Encode(), maxStoredRequestBody)
		}
	case "multipart/form-data":
		var lines []string
		for _, value := range rc.BodyValues {
			switch {
			case strings.HasPrefix(value, "{\"__jingshield_upload__\""):
				lines = append(lines, value)
			case strings.HasPrefix(value, "__jingshield_upload_sample__:"):
				sample := strings.TrimPrefix(value, "__jingshield_upload_sample__:")
				lines = append(lines, "upload_sample="+truncatePacket(redactTextSecrets(cleanBodyText(sample)), 1024))
			}
		}
		if len(lines) > 0 {
			return truncatePacket(strings.Join(lines, "\n"), maxStoredRequestBody)
		}
	}
	return truncatePacket(redactTextSecrets(cleanBodyText(string(rc.RawBody))), maxStoredRequestBody)
}

func redactJSONValue(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if sensitiveField(key) {
				typed[key] = redactedValue
				continue
			}
			redactJSONValue(child)
		}
	case []any:
		for _, child := range typed {
			redactJSONValue(child)
		}
	}
}

func sensitiveHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "x-csrf-token":
		return true
	default:
		return false
	}
}

func sensitiveField(name string) bool {
	normalized := strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(strings.TrimSpace(name)))
	for _, marker := range []string{"password", "passwd", "secret", "token", "apikey", "session", "credential", "authorization", "cookie"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

var secretAssignmentPattern = regexp.MustCompile(`(?i)(["']?(?:password|passwd|secret|token|api[_-]?key|session|credential|authorization|cookie)["']?\s*(?::|=)\s*)(?:"(?:\\.|[^"])*"|'[^']*'|[^\s&;,]+)`)

func redactTextSecrets(value string) string {
	return secretAssignmentPattern.ReplaceAllString(value, `${1}`+redactedValue)
}

func cleanPacketText(value string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(strings.ToValidUTF8(value, "�"))
}

func cleanBodyText(value string) string {
	value = strings.ToValidUTF8(value, "�")
	return strings.Map(func(char rune) rune {
		if char == '\n' || char == '\r' || char == '\t' || char >= 0x20 {
			return char
		}
		return '�'
	}, value)
}

func truncatePacket(value string, max int) string {
	if len(value) <= max {
		return value
	}
	value = value[:max]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value + "\n...[TRUNCATED]"
}
