package operations

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// FormatRFC5424 builds a single UTF-8 JSON event with escaped control characters.
// Static header tokens prevent attacker-controlled host/header log injection.
func FormatRFC5424(cfg SyslogConfig, event Event) []byte {
	severity := 5
	if event.Severity >= 4 {
		severity = 3
	} else if event.Severity <= 1 {
		severity = 6
	}
	payload, _ := json.Marshal(event)
	return []byte(fmt.Sprintf("<%d>1 %s jingshield JingShield - attack - %s", cfg.Facility*8+severity, event.Time.UTC().Format(time.RFC3339Nano), payload))
}

func sendSyslog(ctx context.Context, cfg SyslogConfig, event Event) error {
	dialer := &net.Dialer{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second}
	var connection net.Conn
	var err error
	if cfg.Transport == "tls" {
		host, _, _ := net.SplitHostPort(cfg.Address)
		if cfg.ServerName != "" {
			host = cfg.ServerName
		}
		connection, err = (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}}).DialContext(ctx, "tcp", cfg.Address)
	} else {
		connection, err = dialer.DialContext(ctx, cfg.Transport, cfg.Address)
	}
	if err != nil {
		return err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	deadline := time.Now().Add(time.Duration(cfg.TimeoutSeconds) * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err = connection.SetWriteDeadline(deadline); err != nil {
		return err
	}
	message := FormatRFC5424(cfg, event)
	if cfg.Transport != "udp" {
		message = append([]byte(strconv.Itoa(len(message))+" "), message...)
	}
	written, err := connection.Write(message)
	if err == nil && written != len(message) {
		err = io.ErrShortWrite
	}
	return err
}
