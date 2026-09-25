package api

import (
	"jingshield/internal/operations"
	"net/http"
)

func (a *API) operationsAvailable(w http.ResponseWriter) bool {
	if a.operations == nil {
		writeError(w, http.StatusServiceUnavailable, -503, "WAF 运营服务不可用")
		return false
	}
	return true
}

func (a *API) syslogGet(w http.ResponseWriter, r *http.Request) {
	if !a.operationsAvailable(w) {
		return
	}
	cfg, status, err := a.operations.Syslog(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "success", map[string]any{"config": cfg, "status": status})
}

func (a *API) syslogPut(w http.ResponseWriter, r *http.Request) {
	if !a.operationsAvailable(w) {
		return
	}
	var input operations.SyslogConfig
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, -3, "syslog 参数格式非法")
		return
	}
	if err := input.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, -3, err.Error())
		return
	}
	if err := a.operations.ConfigureSyslog(r.Context(), input); err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "syslog 配置已原子保存；待发送数据不会被删除", nil)
}

func (a *API) syslogSync(w http.ResponseWriter, r *http.Request) {
	if !a.operationsAvailable(w) {
		return
	}
	var input struct {
		RetryFailed bool `json:"retry_failed"`
	}
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, -3, "同步参数非法")
		return
	}
	if err := a.operations.Sync(r.Context(), input.RetryFailed); err != nil {
		writeError(w, http.StatusConflict, -3, "无法同步：请确认 syslog 已启用且持久队列可用")
		return
	}
	a.syslogGet(w, r)
}

func (a *API) linkageGet(w http.ResponseWriter, r *http.Request) {
	if !a.operationsAvailable(w) {
		return
	}
	cfg, status := a.operations.Linkage()
	writeOK(w, "success", map[string]any{"config": cfg, "status": status})
}

func (a *API) linkagePut(w http.ResponseWriter, r *http.Request) {
	if !a.operationsAvailable(w) {
		return
	}
	var input operations.LinkageConfig
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, -3, "联动配置格式非法")
		return
	}
	if err := input.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, -3, err.Error())
		return
	}
	if err := a.operations.ConfigureLinkage(r.Context(), input); err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "联动配置已保存，需要重新验证同协议能力", nil)
}

func (a *API) linkageProbe(w http.ResponseWriter, r *http.Request) {
	if !a.operationsAvailable(w) {
		return
	}
	capabilities, err := a.operations.ProbeLinkage(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, -502, err.Error())
		return
	}
	writeOK(w, "同协议能力验证通过，未执行封禁", capabilities)
}

func (a *API) linkageBlockBatch(w http.ResponseWriter, r *http.Request) {
	if !a.operationsAvailable(w) {
		return
	}
	var input operations.BlockRequest
	if decodeJSON(w, r, &input) != nil {
		writeError(w, http.StatusBadRequest, -3, "批量封禁请求格式非法")
		return
	}
	if err := input.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, -3, err.Error())
		return
	}
	result, err := a.operations.BlockPeer(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusBadGateway, -502, err.Error())
		return
	}
	writeOK(w, "对端已返回封禁处理结果；不等同于 syslog 日志送达", result)
}
