package api

import "testing"

func TestParseDeviceEventFormats(t *testing.T) {
	tests := []struct {
		name, format, body, vendor, eventType, eventIP, message string
		severity                                                int
	}{
		{"generic", "json", `{"device_name":"edr-1","vendor":"Acme EDR","event_type":"malware","severity":9,"src_ip":"203.0.113.8","message":"blocked"}`, "Acme EDR", "malware", "203.0.113.8", "blocked", 9},
		{"cef with spaces", "cef", `CEF:0|Fortinet|FortiGate|7|1001|Web Attack|9|dvchost=fw-1 src=198.51.100.8 msg=SQL injection was blocked`, "Fortinet", "Web Attack", "198.51.100.8", "SQL injection was blocked", 9},
		{"leef", "leef", "LEEF:2.0|IBM|QRadar|7.5|SuspiciousLogin|devName=qradar\tsrc=192.0.2.9\tsev=8\tmsg=blocked", "IBM", "SuspiciousLogin", "192.0.2.9", "blocked", 8},
		{"suricata", "suricata", `{"src_ip":"203.0.113.9","event_type":"alert","host":"ids-1","alert":{"signature":"ET attack","category":"Web Application Attack","severity":1}}`, "Suricata", "Web Application Attack", "203.0.113.9", "ET attack", 9},
		{"wazuh", "wazuh", `{"agent":{"name":"agent-1"},"rule":{"level":12,"description":"root login","groups":["authentication","sshd"]},"data":{"srcip":"198.51.100.10"}}`, "Wazuh", "authentication,sshd", "198.51.100.10", "root login", 10},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event, err := parseDeviceEvent(test.format, []byte(test.body))
			if err != nil {
				t.Fatal(err)
			}
			if event.Vendor != test.vendor || event.EventType != test.eventType || event.EventIP != test.eventIP || event.Message != test.message || event.Severity != test.severity {
				t.Fatalf("event = %#v", event)
			}
		})
	}
}

func TestParseDeviceEventRejectsInvalidInput(t *testing.T) {
	if _, err := parseDeviceEvent("cef", []byte("not-cef")); err == nil {
		t.Fatal("invalid CEF was accepted")
	}
	if _, err := parseDeviceEvent("json", []byte(`{"event_ip":"127.0.0.999","severity":5}`)); err == nil {
		t.Fatal("invalid event IP was accepted")
	}
}
