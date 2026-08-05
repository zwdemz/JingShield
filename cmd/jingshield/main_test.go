package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpListsBootstrapCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := execute([]string{"help"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"migrate", "init", "cert"} {
		if !strings.Contains(stdout.String(), command) {
			t.Errorf("help output does not contain %q", command)
		}
	}
}

func TestRunCertGeneratesPEMWithSAN(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "node.crt"), filepath.Join(dir, "node.key")
	var output bytes.Buffer
	if err := runCert(certPath, keyPath, []string{"waf.example.test", "192.0.2.10"}, 10950, &output); err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.DNSNames[0] != "waf.example.test" || cert.IPAddresses[0].String() != "192.0.2.10" {
		t.Fatalf("unexpected SANs: %#v %#v", cert.DNSNames, cert.IPAddresses)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := runCert(certPath, keyPath, []string{"localhost"}, 1, &output); err == nil {
		t.Fatal("existing certificate was overwritten")
	}
}

func TestUnknownCommandFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := execute([]string{"unknown"}, &stdout, &stderr); err == nil {
		t.Fatal("unknown command unexpectedly succeeded")
	}
}

func TestInitRequiresExplicitUsername(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := execute([]string{"init"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "--username") {
		t.Fatalf("expected explicit username error, got %v", err)
	}
}
