package firewallbridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"jingshield/internal/pkg/iputil"
)

var whitelistSource = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

type whitelistSnapshot struct {
	Revision int64    `json:"revision"`
	Rules    []string `json:"rules"`
	Digest   string   `json:"digest"`
}

type whitelistFile struct {
	Sources map[string]whitelistSnapshot `json:"sources"`
}

func whitelistDigest(rules []string) string {
	sum := sha256.Sum256([]byte(strings.Join(rules, "\n")))
	return hex.EncodeToString(sum[:])
}

func validateWhitelistState(state whitelistFile) error {
	if len(state.Sources) > 16 {
		return errors.New("too many received whitelist sources")
	}
	for source, snapshot := range state.Sources {
		rules, err := iputil.NormalizeWhitelistRules(snapshot.Rules)
		if !whitelistSource.MatchString(source) || snapshot.Revision <= 0 || err != nil || len(rules) != len(snapshot.Rules) || snapshot.Digest != whitelistDigest(rules) {
			return errors.New("received whitelist state is invalid")
		}
		for index := range rules {
			if rules[index] != snapshot.Rules[index] {
				return errors.New("received whitelist state is not normalized")
			}
		}
	}
	return nil
}

func readWhitelistState(path string) (whitelistFile, error) {
	state := whitelistFile{Sources: map[string]whitelistSnapshot{}}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return state, errors.New("whitelist state file is missing regular-file integrity")
	}
	file, err := os.Open(path)
	if err != nil {
		return state, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil || len(data) > 1<<20 {
		return state, errors.New("whitelist state file exceeds 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF || validateWhitelistState(state) != nil {
		return whitelistFile{}, errors.New("whitelist state file is corrupt")
	}
	if state.Sources == nil {
		state.Sources = map[string]whitelistSnapshot{}
	}
	return state, nil
}

func writeWhitelistState(path string, state whitelistFile) error {
	if err := validateWhitelistState(state); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil || len(data) > 1<<20 {
		return errors.New("whitelist state exceeds 1 MiB")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".whitelist-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func (s *Server) whitelistPrefixes(state whitelistFile) []netip.Prefix {
	prefixes := append([]netip.Prefix{}, s.baseProtected...)
	sources := make([]string, 0, len(state.Sources))
	for source := range state.Sources {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	for _, source := range sources {
		for _, rule := range state.Sources[source].Rules {
			if address, err := netip.ParseAddr(rule); err == nil {
				prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
			} else {
				prefix, _ := netip.ParsePrefix(rule)
				prefixes = append(prefixes, prefix)
			}
		}
	}
	return prefixes
}
