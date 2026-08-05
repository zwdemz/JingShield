package api

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"jingshield/internal/model"
	"jingshield/internal/repository"
)

var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type siteInput struct {
	Name          string `json:"name"`
	Host          string `json:"host"`
	Upstream      string `json:"upstream"`
	Enabled       bool   `json:"enabled"`
	PassHost      bool   `json:"pass_host"`
	TLSSkipVerify bool   `json:"tls_skip_verify"`
}

func (a *API) siteList(w http.ResponseWriter, r *http.Request) {
	list, err := a.sites.List(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "success", list)
}

func (a *API) siteCreate(w http.ResponseWriter, r *http.Request) {
	var in siteInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, -3, "站点参数格式错误")
		return
	}
	site, message := validatedSite(in)
	if message != "" {
		writeError(w, http.StatusBadRequest, -3, message)
		return
	}
	if err := a.sites.Create(r.Context(), site); err != nil {
		a.internalError(w, r, err)
		return
	}
	writeOK(w, "防护站点已创建", site)
}

func (a *API) siteUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := siteID(w, r)
	if !ok {
		return
	}
	var in siteInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, -3, "站点参数格式错误")
		return
	}
	site, message := validatedSite(in)
	if message != "" {
		writeError(w, http.StatusBadRequest, -3, message)
		return
	}
	site.ID = id
	if err := a.sites.Update(r.Context(), site); err != nil {
		a.siteRepoError(w, r, err)
		return
	}
	writeOK(w, "防护站点已更新", site)
}

func (a *API) siteStatusPut(w http.ResponseWriter, r *http.Request) {
	id, ok := siteID(w, r)
	if !ok {
		return
	}
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decodeJSON(w, r, &in); err != nil || in.Enabled == nil {
		writeError(w, http.StatusBadRequest, -3, "enabled 必须是布尔值")
		return
	}
	if err := a.sites.SetEnabled(r.Context(), id, *in.Enabled); err != nil {
		a.siteRepoError(w, r, err)
		return
	}
	writeOK(w, "站点状态已更新", nil)
}

func (a *API) siteDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := siteID(w, r)
	if !ok {
		return
	}
	if err := a.sites.Delete(r.Context(), id); err != nil {
		a.siteRepoError(w, r, err)
		return
	}
	writeOK(w, "防护站点已删除", nil)
}

func (a *API) siteRepoError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, repository.ErrSiteNotFound) {
		writeError(w, http.StatusNotFound, -404, err.Error())
		return
	}
	a.internalError(w, r, err)
}

func siteID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, -3, "站点 ID 非法")
		return 0, false
	}
	return id, true
}

func validatedSite(in siteInput) (*model.Site, string) {
	in.Name = strings.TrimSpace(in.Name)
	if len(in.Name) < 1 || len(in.Name) > 100 {
		return nil, "站点名称长度必须为 1-100 个字符"
	}
	host, ok := normalizeSiteHost(in.Host)
	if !ok {
		return nil, "防护域名格式错误，仅支持域名、IP 或 *.example.com"
	}
	upstream, ok := normalizeUpstream(in.Upstream)
	if !ok {
		return nil, "源站必须是合法的 http:// 或 https:// 地址，且不能包含账号、查询参数或片段"
	}
	if in.TLSSkipVerify && !strings.HasPrefix(upstream, "https://") {
		return nil, "仅 HTTPS 源站可以启用跳过证书校验"
	}
	return &model.Site{Name: in.Name, Host: host, Upstream: upstream, Enabled: in.Enabled, PassHost: in.PassHost, TLSSkipVerify: in.TLSSkipVerify}, ""
}

func normalizeSiteHost(value string) (string, bool) {
	host := strings.ToLower(strings.TrimSpace(value))
	host = strings.TrimSuffix(host, ".")
	if len(host) < 1 || len(host) > 255 || strings.ContainsAny(host, "/:@?#[]") {
		if net.ParseIP(strings.Trim(host, "[]")) != nil {
			return strings.Trim(host, "[]"), true
		}
		return "", false
	}
	if net.ParseIP(host) != nil {
		return host, true
	}
	base := host
	if strings.HasPrefix(base, "*.") {
		base = strings.TrimPrefix(base, "*.")
		if !strings.Contains(base, ".") {
			return "", false
		}
	} else if strings.Contains(base, "*") {
		return "", false
	}
	for _, label := range strings.Split(base, ".") {
		if !dnsLabelPattern.MatchString(label) {
			return "", false
		}
	}
	return host, true
}

func normalizeUpstream(value string) (string, bool) {
	value = strings.TrimSpace(value)
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	u.Scheme = strings.ToLower(u.Scheme)
	return strings.TrimSuffix(u.String(), "/"), true
}
