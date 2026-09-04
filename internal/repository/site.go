package repository

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"jingshield/internal/model"
)

var ErrSiteNotFound = errors.New("防护站点不存在")

// SiteRepo persists sites and maintains a short-lived routing cache. API writes
// invalidate the same instance immediately; the TTL also covers external DB edits.
type SiteRepo struct {
	db *sql.DB

	mu       sync.RWMutex
	routes   map[string]*model.Site
	hasSites bool
	loadedAt time.Time
}

func NewSiteRepo(db *sql.DB) *SiteRepo { return &SiteRepo{db: db} }

func (r *SiteRepo) List(ctx context.Context) ([]*model.Site, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, name, host, upstream, enabled, pass_host, tls_skip_verify, created_at, updated_at
		FROM jyj_sites ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := make([]*model.Site, 0)
	for rows.Next() {
		s := &model.Site{}
		if err := rows.Scan(&s.ID, &s.Name, &s.Host, &s.Upstream, &s.Enabled, &s.PassHost, &s.TLSSkipVerify, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, s)
	}
	return list, rows.Err()
}

// GetByID returns one site for administrative operations that need to inspect
// the configured upstream without affecting the routing cache.
func (r *SiteRepo) GetByID(ctx context.Context, id int64) (*model.Site, error) {
	s := &model.Site{}
	err := r.db.QueryRowContext(ctx, `SELECT id, name, host, upstream, enabled, pass_host, tls_skip_verify, created_at, updated_at
		FROM jyj_sites WHERE id = ?`, id).Scan(
		&s.ID, &s.Name, &s.Host, &s.Upstream, &s.Enabled, &s.PassHost, &s.TLSSkipVerify, &s.CreatedAt, &s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSiteNotFound
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (r *SiteRepo) Create(ctx context.Context, s *model.Site) error {
	result, err := r.db.ExecContext(ctx, `INSERT INTO jyj_sites (name, host, upstream, enabled, pass_host, tls_skip_verify)
		VALUES (?, ?, ?, ?, ?, ?)`, s.Name, s.Host, s.Upstream, s.Enabled, s.PassHost, s.TLSSkipVerify)
	if err != nil {
		return err
	}
	s.ID, _ = result.LastInsertId()
	r.Invalidate()
	return nil
}

func (r *SiteRepo) Update(ctx context.Context, s *model.Site) error {
	result, err := r.db.ExecContext(ctx, `UPDATE jyj_sites SET name = ?, host = ?, upstream = ?, enabled = ?, pass_host = ?, tls_skip_verify = ? WHERE id = ?`,
		s.Name, s.Host, s.Upstream, s.Enabled, s.PassHost, s.TLSSkipVerify, s.ID)
	if err != nil {
		return err
	}
	return r.changed(result)
}

func (r *SiteRepo) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	result, err := r.db.ExecContext(ctx, "UPDATE jyj_sites SET enabled = ? WHERE id = ?", enabled, id)
	if err != nil {
		return err
	}
	return r.changed(result)
}

func (r *SiteRepo) Delete(ctx context.Context, id int64) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM jyj_sites WHERE id = ?", id)
	if err != nil {
		return err
	}
	return r.changed(result)
}

func (r *SiteRepo) changed(result sql.Result) error {
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrSiteNotFound
	}
	r.Invalidate()
	return nil
}

func (r *SiteRepo) Invalidate() {
	r.mu.Lock()
	r.loadedAt = time.Time{}
	r.mu.Unlock()
}

// ResolveSite selects an enabled site by the HTTP Host header. hasSites is
// true even when every configured site is disabled, allowing the proxy to
// reject unknown/disabled hosts instead of falling back unexpectedly.
func (r *SiteRepo) ResolveSite(ctx context.Context, requestHost string) (site *model.Site, hasSites bool, err error) {
	host := canonicalRequestHost(requestHost)
	r.mu.RLock()
	fresh := !r.loadedAt.IsZero() && time.Since(r.loadedAt) < 10*time.Second
	if fresh {
		site, hasSites = matchSite(r.routes, host), r.hasSites
		r.mu.RUnlock()
		return cloneSite(site), hasSites, nil
	}
	r.mu.RUnlock()

	if err := r.reload(ctx); err != nil {
		return nil, false, err
	}
	r.mu.RLock()
	site, hasSites = matchSite(r.routes, host), r.hasSites
	r.mu.RUnlock()
	return cloneSite(site), hasSites, nil
}

func (r *SiteRepo) reload(ctx context.Context) error {
	list, err := r.List(ctx)
	if err != nil {
		return err
	}
	routes := make(map[string]*model.Site, len(list))
	for _, site := range list {
		if site.Enabled {
			routes[site.Host] = cloneSite(site)
		}
	}
	r.mu.Lock()
	r.routes, r.hasSites, r.loadedAt = routes, len(list) > 0, time.Now()
	r.mu.Unlock()
	return nil
}

func canonicalRequestHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	return strings.TrimSuffix(strings.Trim(host, "[]"), ".")
}

func matchSite(routes map[string]*model.Site, host string) *model.Site {
	if exact := routes[host]; exact != nil {
		return exact
	}
	var best *model.Site
	for pattern, site := range routes {
		if !strings.HasPrefix(pattern, "*.") {
			continue
		}
		suffix := pattern[1:]
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) && (best == nil || len(pattern) > len(best.Host)) {
			best = site
		}
	}
	return best
}

func cloneSite(site *model.Site) *model.Site {
	if site == nil {
		return nil
	}
	copy := *site
	return &copy
}
