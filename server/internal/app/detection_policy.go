package app

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"slices"
	"strings"
)

type DiscoveryConfig struct {
	Enabled        bool     `json:"enabled"`
	IgnoredDomains []string `json:"ignored_domains"`
}

// BlockedPlatform is a known platform the Enterprise extension blocks: its catalogue hosts
// and, for a platform living under a path of a shared host, the path prefixes to block.
type BlockedPlatform struct {
	ID      string   `json:"id"`
	Domains []string `json:"domains"`
	Paths   []string `json:"paths,omitempty"`
}

func modelPlatformShape(id, channel string) bool {
	return categoryPattern.MatchString(id) && len(id) <= 64 && (channel == "browser" && !slices.Contains([]string{"codex", "claude-code", "claude-desktop", "claude-desktop-agent"}, id) || channel == "native" && Edition == "commercial" && validModelPlatform(id, channel))
}
func (a *App) validateCatalogPolicy(ctx context.Context, tx pgx.Tx, c ShadowConfig) error {
	_, _, cat, e := currentDetection(ctx, tx)
	if e != nil {
		return e
	}
	known := map[string]DetectionProvider{}
	for _, p := range cat.Providers {
		known[p.ID] = p
	}
	for _, s := range c.Services {
		p, ok := known[s.ID]
		if !ok || !slices.Equal(p.Domains, s.Domains) {
			return bad("A service must use the current catalogue domains.")
		}
	}
	for _, rule := range c.ModelAccess {
		if rule.Channel == "browser" {
			if _, ok := known[rule.PlatformID]; !ok {
				return bad("Unknown catalogue platform.")
			}
		} else if !validModelPlatform(rule.PlatformID, "native") {
			return bad("Unknown native platform.")
		}
	}
	return nil
}
func (a *App) enrichDetectionPolicy(ctx context.Context, tx pgx.Tx, org string, out *ShadowSettings) error {
	rev, _, cat, e := currentDetection(ctx, tx)
	if e != nil {
		return e
	}
	p, e := a.readPrivacy(ctx, tx, org)
	if e != nil {
		return e
	}
	previous := map[string]ServiceConfig{}
	for _, s := range out.Config.Services {
		previous[s.ID] = s
	}
	out.Config.Services = []ServiceConfig{}
	for _, provider := range cat.Providers {
		s, ok := previous[provider.ID]
		if !ok {
			s = ServiceConfig{ID: provider.ID, Mode: "observe", Enabled: true}
		}
		s.Domains = append([]string{}, provider.Domains...)
		out.Config.Services = append(out.Config.Services, s)
	}
	out.Config.Discovery = DiscoveryConfig{p.Config.DiscoveryEnabled, append([]string{}, p.Config.IgnoredDomains...)}
	rows, e := tx.Query(ctx, "SELECT domain FROM candidate_domains WHERE status='ignored'")
	if e != nil {
		return e
	}
	for rows.Next() {
		var domain string
		if e = rows.Scan(&domain); e != nil {
			rows.Close()
			return e
		}
		if !slices.Contains(out.Config.Discovery.IgnoredDomains, domain) {
			out.Config.Discovery.IgnoredDomains = append(out.Config.Discovery.IgnoredDomains, domain)
		}
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return e
	}
	out.Revision += rev + p.Revision
	// Derived here on every read, like discovery, never saved from a client.
	if out.Config.BlockedPlatforms, e = blockedPlatformPolicy(ctx, tx, cat); e != nil {
		return e
	}
	if Edition == "commercial" {
		out.ModelCatalog = []ModelCatalogEntry{}
		for _, provider := range cat.Providers {
			out.ModelCatalog = append(out.ModelCatalog, ModelCatalogEntry{provider.ID, "browser", provider.Label, provider.Domains[0], []string{}})
		}
		for _, entry := range modelCatalog() {
			if entry.Channel == "native" {
				out.ModelCatalog = append(out.ModelCatalog, entry)
			}
		}
	}
	return nil
}

// A catalogue is immutable by revision. Reuse its decoded form only within this
// request's transaction, never across requests or across authorization changes.
type detectionEventBatch struct {
	catalogs map[int64]DetectionContent
	blocked  map[string]bool
}

func (b *detectionEventBatch) authorize(ctx context.Context, tx pgx.Tx, v *V2Event) error {
	if Edition == "community" {
		// The model that answered is inventory and belongs to both editions: an
		// administrator has to see what is actually used. Only the *decision* is
		// Proprietary, and that is what the next three fields carry -- the platform a
		// rule was evaluated for and why it refused. Clearing the model here left
		// every Community record blank while the agent and the extension had already
		// been corrected to report it (product decision, 2026-09-14).
		v.InputTokens = nil
		v.OutputTokens = nil
		v.PlatformID = ""
		v.DecisionReason = ""
	}
	if v.Source == "native" {
		return nil
	}
	revision := int64(0)
	if v.CatalogRevision != nil && *v.CatalogRevision > 0 {
		revision = *v.CatalogRevision
	}
	cat, e := b.catalog(ctx, tx, revision)
	if e != nil {
		return e
	}
	host := strings.ToLower(v.Provider)
	// A covered provider is checked first and wins: where the catalogue carries selectors
	// and rules, full capture is better than presence, and the same host must not be
	// counted twice. This precedence is what lets one published catalogue name a platform
	// that Enterprise covers and Community does not.
	for _, p := range cat.Providers {
		if slices.Contains(p.Domains, host) {
			if v.PlatformID != "" && v.PlatformID != p.ID {
				v.PlatformID = ""
			}
			return nil
		}
	}
	for _, p := range cat.KnownPlatforms {
		if slices.Contains(p.Domains, host) {
			reducedToPresence(v)
			// A blocked attempt is only one where the organization blocks this platform:
			// otherwise a modified endpoint could fill Discovery with attempts for platforms
			// nobody blocked. Community never blocks, and reads an empty set.
			if v.Action == "blocked" {
				if b.blocked == nil {
					if b.blocked, e = blockedPlatformSet(ctx, tx); e != nil {
						return e
					}
					if b.blocked == nil {
						b.blocked = map[string]bool{}
					}
				}
				if !b.blocked[p.ID] {
					v.Action = "observed"
				}
			}
			return nil
		}
	}
	v.Provider = "unknown"
	v.PlatformID = ""
	v.DecisionReason = ""
	v.URL = ""
	return nil
}

func (b *detectionEventBatch) catalog(ctx context.Context, tx pgx.Tx, revision int64) (DetectionContent, error) {
	if cached, found := b.catalogs[revision]; found {
		return cached, nil
	}
	var cat DetectionContent
	raw := detectionFactory
	if revision > 0 {
		raw = nil
		e := tx.QueryRow(ctx, "SELECT content FROM detection_catalogs WHERE revision=$1 AND (created_at>now()-interval '30 days' OR revision=(SELECT max(revision) FROM detection_catalogs))", revision).Scan(&raw)
		if e != nil && e != pgx.ErrNoRows {
			return cat, e
		}
	}
	if len(raw) > 0 {
		if e := json.Unmarshal(raw, &cat); e != nil {
			return cat, e
		}
	}
	restrictEditionProviders(&cat)
	if b.catalogs == nil {
		b.catalogs = map[int64]DetectionContent{}
	}
	b.catalogs[revision] = cat
	return cat, nil
}

// reducedToPresence keeps the platform and throws away everything else. The endpoint is
// meant to send nothing more, but the guarantee belongs here: a modified extension that
// attached a URL, a prompt or a conversation identifier to a presence record must not
// succeed in having it stored.
//
// The OS account is the one exception, in both editions: the agent stamps the account
// behind the browser connection, so the record says which person was signed in at the
// time rather than who is signed in now. It stays under the organization's
// pseudonymisation like every other record's account.
func reducedToPresence(v *V2Event) {
	v.Detector = "presence"
	v.URL = ""
	v.ConversationID = ""
	v.CorrelationID = ""
	v.Model = ""
	v.Effort = ""
	v.Session = ""
	v.Characters = 0
	v.Labels = nil
	v.Files = nil
	v.Prompt = nil
	v.Response = nil
	v.PlatformID = ""
	v.DecisionReason = ""
}
