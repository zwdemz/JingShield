package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"jingshield/internal/operations"
	"jingshield/internal/pkg/iputil"
	"jingshield/internal/repository"
)

func (a *API) receivedWhitelistGet(w http.ResponseWriter, r *http.Request) {
	sources, err := a.ipList.ReceivedWhitelist(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "success", sources)
}

func (a *API) whitelistPreview(w http.ResponseWriter, r *http.Request) {
	if !a.operationsAvailable(w) {
		return
	}
	rules, err := a.ipList.ManualWhitelistSnapshot(r.Context())
	if err != nil {
		writeError(w, http.StatusConflict, -3, "本机白名单不符合对端同步格式或超过 500 条，请先调整规则")
		return
	}
	config, _ := a.operations.Linkage()
	digest := sha256.Sum256([]byte(strings.Join(rules, "\n")))
	writeOK(w, "success", map[string]any{"source": config.SourceID, "count": len(rules), "rules": rules, "digest": hex.EncodeToString(digest[:])})
}

func (a *API) whitelistPush(w http.ResponseWriter, r *http.Request) {
	if !a.operationsAvailable(w) {
		return
	}
	var input struct {
		ExpectedDigest string `json:"expected_digest"`
	}
	if err := decodeJSON(w, r, &input); err != nil || len(input.ExpectedDigest) != 64 {
		writeError(w, http.StatusBadRequest, -3, "请先预览并确认当前白名单快照")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	rules, err := a.ipList.ManualWhitelistSnapshot(ctx)
	if err != nil {
		writeError(w, http.StatusConflict, -3, "本机白名单无法完整下发，请检查规则与 500 条上限")
		return
	}
	digest := sha256.Sum256([]byte(strings.Join(rules, "\n")))
	if input.ExpectedDigest != hex.EncodeToString(digest[:]) {
		writeError(w, http.StatusConflict, -3, "白名单已变化，请重新预览后下发")
		return
	}
	config, _ := a.operations.Linkage()
	result, err := a.operations.PushWhitelist(ctx, operations.WhitelistRequest{Source: config.SourceID, Revision: time.Now().UnixMicro(), Rules: rules})
	if err != nil {
		writeError(w, http.StatusBadGateway, -502, err.Error())
		return
	}
	writeOK(w, "对端已确认接收该来源的完整白名单快照", result)
}

func (a *API) openAPIWhitelistSync(w http.ResponseWriter, r *http.Request) {
	var input operations.WhitelistRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, -3, "白名单快照格式非法")
		return
	}
	if !repository.ValidWhitelistSource(input.Source) || input.Revision <= 0 {
		writeError(w, http.StatusBadRequest, -3, "来源或版本号无效")
		return
	}
	if _, err := iputil.NormalizeWhitelistRules(input.Rules); err != nil {
		writeError(w, http.StatusBadRequest, -3, "白名单规则无效或超过 500 条")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	result, err := a.ipList.SyncWhitelist(ctx, input.Source, input.Revision, input.Rules)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, repository.ErrStaleWhitelist) || errors.Is(err, repository.ErrWhitelistConflict) {
			status = http.StatusConflict
		} else if !repository.ValidWhitelistSource(input.Source) || input.Revision <= 0 {
			status = http.StatusBadRequest
		} else {
			a.internalError(w, r, err)
			return
		}
		writeError(w, status, -3, err.Error())
		return
	}
	writeOK(w, "白名单快照已接收", result)
}
