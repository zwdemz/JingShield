package firewallbridge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"time"

	"jingshield/internal/pkg/iputil"
)

type whitelistInput struct {
	Source   string   `json:"source"`
	Revision int64    `json:"revision"`
	Rules    []string `json:"rules"`
}

// whitelistSync accepts one source-owned complete snapshot. Static management
// and administrator allowlists are never replaced. Durable state is written
// before removing managed blocks; a failed kernel readback remains unconfirmed.
func (s *Server) whitelistSync(w http.ResponseWriter, r *http.Request, source netip.Addr) {
	if s.config.WhitelistStateFile == "" {
		s.reply(w, 503, -503, "whitelist state file is not configured", nil)
		return
	}
	var input whitelistInput
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF || !whitelistSource.MatchString(input.Source) || input.Revision <= 0 {
		s.reply(w, 400, -400, "invalid whitelist source, revision or JSON body", nil)
		return
	}
	rules, err := iputil.NormalizeWhitelistRules(input.Rules)
	if err != nil {
		s.reply(w, 400, -400, "invalid or oversized whitelist rules", nil)
		return
	}
	select {
	case s.active <- struct{}{}:
		defer func() { <-s.active }()
	default:
		s.reply(w, 429, -429, "another batch is in progress", nil)
		return
	}
	digest := whitelistDigest(rules)
	previous, found := s.whitelist.Sources[input.Source]
	if found && (input.Revision < previous.Revision || input.Revision == previous.Revision && digest != previous.Digest) {
		s.reply(w, 409, -409, "stale or conflicting whitelist revision", nil)
		return
	}
	if !found && len(s.whitelist.Sources) >= 16 {
		s.reply(w, 400, -400, "maximum whitelist source count reached", nil)
		return
	}
	result := map[string]any{"source": input.Source, "revision": input.Revision, "count": len(rules), "digest": digest, "dry_run": !s.config.Apply}
	event := AuditEvent{Time: time.Now().UTC(), Action: "whitelist_requested", SourceIP: source.String(), Driver: s.driver.Name(), WhitelistSource: input.Source, Revision: input.Revision, RuleCount: len(rules), DryRun: !s.config.Apply}
	if s.audit(event) != nil {
		s.reply(w, 503, -503, "audit unavailable; no whitelist change applied", nil)
		return
	}
	if !found || input.Revision > previous.Revision {
		updated := whitelistFile{Sources: make(map[string]whitelistSnapshot, len(s.whitelist.Sources)+1)}
		for peer, snapshot := range s.whitelist.Sources {
			updated.Sources[peer] = snapshot
		}
		updated.Sources[input.Source] = whitelistSnapshot{Revision: input.Revision, Rules: rules, Digest: digest}
		if s.config.Apply {
			if err := writeWhitelistState(s.config.WhitelistStateFile, updated); err != nil {
				s.reply(w, 503, -503, "whitelist state could not be saved", nil)
				return
			}
		}
		s.whitelist = updated
		s.protected = s.whitelistPrefixes(updated)
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.config.RequestTimeoutSeconds)*time.Second)
	defer cancel()
	removed := 0
	if cleaner, ok := s.driver.(WhitelistCleaner); ok {
		removed, err = cleaner.ClearMatching(ctx, s.protected)
	} else {
		err = io.ErrUnexpectedEOF
	}
	event.Time = time.Now().UTC()
	event.Applied = removed
	event.Action = "whitelist_confirmed"
	if !s.config.Apply {
		event.Action = "whitelist_preview"
	}
	if err != nil {
		event.Action = "whitelist_unconfirmed"
		event.Partial = true
	}
	if s.audit(event) != nil {
		s.reply(w, 503, -503, "whitelist changed but outcome audit failed; inspect state", result)
		return
	}
	if err != nil {
		s.reply(w, 502, -502, "whitelist saved but managed block cleanup is unconfirmed", result)
		return
	}
	s.reply(w, 200, 0, "success", result)
}
