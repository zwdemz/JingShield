package api

import (
	"context"
	"jingshield/internal/pkg/iputil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type blockBatchInput struct {
	IPs           []string `json:"ips"`
	Reason        string   `json:"reason"`
	ExpireSeconds int      `json:"expire_seconds"`
}

func (a *API) ipBlockBatch(w http.ResponseWriter, r *http.Request) {
	a.blockBatch(w, r, "admin:"+strconv.FormatInt(currentSession(r).UserID, 10))
}

func (a *API) openAPIBlockBatch(w http.ResponseWriter, r *http.Request) {
	a.blockBatch(w, r, "openapi")
}

func (a *API) blockBatch(w http.ResponseWriter, r *http.Request, actor string) {
	var input blockBatchInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, 400, -3, "批量封禁请求格式非法")
		return
	}
	if _, err := iputil.NormalizeBlockIPs(input.IPs); err != nil {
		writeError(w, 400, -3, err.Error())
		return
	}
	if !iputil.ValidBlockReason(input.Reason) || input.ExpireSeconds < 0 || input.ExpireSeconds > 31536000 {
		writeError(w, 400, -3, "须填写 1-255 字节封禁原因，有效期为 0-31536000 秒")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	result, err := a.ipList.BlockBatch(ctx, input.IPs, strings.TrimSpace(input.Reason), input.ExpireSeconds, actor)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "批量封禁已完成，白名单 IP 已跳过", result)
}

func (a *API) openAPICapabilities(w http.ResponseWriter, _ *http.Request) {
	writeOK(w, "success", map[string]any{"protocol": "jingshield-v1", "device_type": "waf", "capabilities": []string{"block-batch", "whitelist-sync"}, "max_batch_size": iputil.MaxBlockBatch, "max_expire_seconds": 31536000})
}
