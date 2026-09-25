// jingshield-firewall is a separate least-privilege HTTPS adapter process. The
// main WAF never receives CAP_NET_ADMIN or a general-purpose command interface.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"jingshield/internal/firewallbridge"
)

func main() {
	configPath := flag.String("config", "/etc/jingshield-firewall/config.json", "validated JSON configuration")
	flag.Parse()
	if err := run(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, "firewall adapter:", err)
		os.Exit(1)
	}
}

func run(path string) error {
	cfg, err := firewallbridge.LoadConfig(path)
	if err != nil {
		return err
	}
	var driver firewallbridge.Driver = firewallbridge.NewDryRunDriver()
	if cfg.Apply {
		if cfg.Backend == "nftables" {
			driver = firewallbridge.NewNFTDriver(nil)
		} else {
			driver = firewallbridge.NewIPSetDriver(nil)
		}
	}
	var auditMu sync.Mutex
	encoder := json.NewEncoder(os.Stdout)
	bridge, err := firewallbridge.NewServer(cfg, driver, func(event firewallbridge.AuditEvent) error {
		auditMu.Lock()
		defer auditMu.Unlock()
		return encoder.Encode(event)
	})
	if err != nil {
		return err
	}
	unlock, err := acquireInstanceLock()
	if err != nil {
		return err
	}
	defer unlock()
	server := bridge.HTTPServer()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	finished := make(chan error, 1)
	go func() { finished <- server.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey) }()
	select {
	case err := <-finished:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
