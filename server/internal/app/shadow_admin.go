package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
)

func criteriaValues(criteria map[string]json.RawMessage) (url.Values, error) {
	q := url.Values{}
	for k, raw := range criteria {
		if k != "from" && k != "to" && k != "actor_id" && k != "device_id" && k != "tool" && k != "provider" && k != "model" && k != "sensitivity" && k != "action" && k != "query" && k != "kind" && k != "attachment" {
			return nil, bad("Unknown saved filter field.")
		}
		var single string
		if json.Unmarshal(raw, &single) == nil {
			q.Add(k, single)
			continue
		}
		var values []string
		if json.Unmarshal(raw, &values) != nil {
			return nil, bad("Filter values must be text or arrays of text.")
		}
		for _, v := range values {
			q.Add(k, v)
		}
	}
	return q, nil
}
func (a *App) savedShadowFilters(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	return jsonQuery(w, r, tx, `SELECT jsonb_build_object('items',coalesce(jsonb_agg(x ORDER BY x.name,x.id),'[]'::jsonb)) FROM (SELECT id,name,shared,user_id AS owner_id,filters AS criteria FROM shadow_saved_filters WHERE user_id=$1 OR shared=true) x`, s.UserID)
}
func (a *App) saveShadowFilter(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var body struct {
		Name     string                     `json:"name"`
		Shared   bool                       `json:"shared"`
		Criteria map[string]json.RawMessage `json:"criteria"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if !validMetadata(body.Name, 120) {
		return bad("A filter name must contain 1 to 120 characters.")
	}
	q, e := criteriaValues(body.Criteria)
	if e != nil {
		return e
	}
	f, e := parseShadowFilter(q)
	if e != nil {
		return e
	}
	raw, _ := json.Marshal(f.Criteria)
	id := r.PathValue("id")
	status := 200
	if id == "" {
		if e = tx.QueryRow(r.Context(), `INSERT INTO shadow_saved_filters(organization_id,user_id,name,shared,filters) VALUES($1,$2,$3,$4,$5) RETURNING id`, s.OrganizationID, s.UserID, body.Name, body.Shared, raw).Scan(&id); e != nil {
			return e
		}
		status = 201
	} else {
		if !uuidPattern.MatchString(id) {
			return bad("Invalid filter ID.")
		}
		tag, e := tx.Exec(r.Context(), `UPDATE shadow_saved_filters SET name=$1,shared=$2,filters=$3,updated_at=now() WHERE id=$4 AND (user_id=$5 OR (shared AND $6))`, body.Name, body.Shared, raw, id, s.UserID, hasPermission(s.Permissions, permPolicyManage))
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			return apiError{404, "not_found", "Filter not found or not editable."}
		}
	}
	if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, "shadow.filter.save", id); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, status, map[string]string{"id": id})
	return nil
}
func (a *App) deleteShadowFilter(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad("Invalid filter ID.")
	}
	tag, e := tx.Exec(r.Context(), `DELETE FROM shadow_saved_filters WHERE id=$1 AND (user_id=$2 OR (shared AND $3))`, id, s.UserID, hasPermission(s.Permissions, permPolicyManage))
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		return apiError{404, "not_found", "Filter not found or not editable."}
	}
	if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, "shadow.filter.delete", id); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) purgeContent(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	// A FRESH second factor, not merely one presented at sign-in. `s.MFA` is evidence
	// from the login, and a session lives eight hours: gating an irreversible mass
	// DELETE on it meant an eight-hour-old assertion was enough. Every comparable act
	// already demands the five-minute check -- PUT /api/privacy, identity reveal and
	// erase, catalogue publication and import, LDAP configuration. An adversarial review
	// on 2026-09-21 measured this route answering 200 to a session whose
	// mfa_verified_at was two hours old, and to one where it was NULL.
	if e := a.requireFreshMFA(r, tx, s); e != nil {
		return e
	}
	var body struct {
		Before time.Time `json:"before"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if body.Before.IsZero() || body.Before.After(time.Now().Add(time.Minute)) {
		return bad("Provide a valid cutoff date.")
	}
	tag, e := tx.Exec(r.Context(), `DELETE FROM shadow_content c USING shadow_events e WHERE c.organization_id=e.organization_id AND c.device_id=e.device_id AND c.event_id=e.id AND e.occurred_at<$1`, body.Before)
	if e != nil {
		return e
	}
	if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, "shadow.content.purge", body.Before.UTC().Format(time.RFC3339)); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]int64{"deleted": tag.RowsAffected()})
	return nil
}
func (a *App) shadowOperations(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	versions := []any{}
	for _, edition := range []string{"community", "commercial"} {
		if edition == "commercial" && Edition != "commercial" {
			continue
		}
		for _, platform := range []string{"windows", "linux"} {
			_, manifest, err := a.readUpdateManifest(edition, platform)
			if err == nil && a.releaseArtifactReady(manifest) {
				versions = append(versions, map[string]any{"version": manifest.Version, "edition": manifest.Edition, "platform": manifest.Platform, "expires_at": manifest.ExpiresAt})
			}
		}
	}
	reason := ""
	if !a.updatesAvailable() {
		reason = "No signed release directory and verification key are configured."
	}
	// What each device reports belongs to that device: Parc → Postes shows it on
	// the device page, from GET /api/devices.
	reply(w, 200, map[string]any{"updates": map[string]any{"available": a.updatesAvailable(), "reason": reason, "versions": versions}})
	return nil
}

// shadowMetrics answers the organization's 24-hour counters. It is no longer a
// policy setting: the route is open unless the deployment closes it with
// MILVAGO_SHADOW_METRICS. Reading it still requires a console session and
// policy.manage.
func (a *App) shadowMetrics(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if !a.config.ShadowMetrics {
		return apiError{404, "metrics_disabled", "Metrics are disabled on this server."}
	}
	if r.URL.Query().Get("format") == "prometheus" {
		var prompts, responses, navigations, blocked int64
		if e := tx.QueryRow(r.Context(), `SELECT count(*) FILTER(WHERE kind='prompt'),count(*) FILTER(WHERE kind='response'),count(*) FILTER(WHERE kind='navigation'),count(*) FILTER(WHERE action='blocked') FROM shadow_events e WHERE occurred_at>=now()-interval '24 hours' AND NOT `+attachmentOnly("e")).Scan(&prompts, &responses, &navigations, &blocked); e != nil {
			return e
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, e := fmt.Fprintf(w, "# HELP milvago_shadow_events_24h Events in this organization over the last 24 hours.\n# TYPE milvago_shadow_events_24h gauge\nmilvago_shadow_events_24h{kind=\"prompt\"} %d\nmilvago_shadow_events_24h{kind=\"response\"} %d\nmilvago_shadow_events_24h{kind=\"navigation\"} %d\n# TYPE milvago_shadow_blocked_24h gauge\nmilvago_shadow_blocked_24h %d\n", prompts, responses, navigations, blocked)
		return e
	}
	return jsonQuery(w, r, tx, `SELECT jsonb_build_object('events',count(*),'prompts',count(*) FILTER(WHERE kind='prompt'),'responses',count(*) FILTER(WHERE kind='response'),'navigations',count(*) FILTER(WHERE kind='navigation'),'blocked',count(*) FILTER(WHERE action='blocked')) FROM shadow_events e WHERE occurred_at>=now()-interval '24 hours' AND NOT `+attachmentOnly("e"))
}
func (a *App) registerShadowRoutes() {
	a.mux.HandleFunc("GET /v3/policy", a.v3Policy)
	a.mux.HandleFunc("POST /v3/enforcement", a.deviceFirst(a.modelEnforcement))
	// Per-model control is an Enterprise capability: Community does not expose its
	// console status route, and the /api/ catch-all answers 404 for this edition.
	if Edition == "commercial" {
		a.console("GET /api/model-access/status", permOverviewRead, a.modelAccessStatus)
	}
	a.mux.HandleFunc("GET /v2/update", a.updateManifest)
	a.mux.HandleFunc("GET /v2/update/anchor", a.updateAnchor)
	a.mux.HandleFunc("GET /v2/update/artifact/{sha256}", a.updateArtifact)
	a.mux.HandleFunc("POST /v2/update/status", a.deviceFirst(a.updateStatus))
	a.mux.HandleFunc("POST /v2/heartbeat", a.deviceFirst(a.deviceHeartbeat))
	a.mux.HandleFunc("POST /v2/identity/start", a.deviceFirst(a.startDeviceAssociation))
	a.mux.HandleFunc("DELETE /v2/identity", a.unbindDeviceAssociation)
	a.mux.HandleFunc("GET /auth/device", a.deviceAssociation)
	a.mux.HandleFunc("POST /auth/device", a.deviceAssociation)
	a.console("GET /api/shadow/settings", permPolicyManage, a.shadowSettings)
	a.console("PUT /api/shadow/settings", permPolicyManage, a.putShadowSettings)
	a.console("GET /api/devices/{id}/shadow", permPolicyManage, a.deviceShadow)
	a.console("PUT /api/devices/{id}/shadow", permPolicyManage, a.putDeviceShadow)
	a.console("GET /api/shadow/events", permEventsRead, a.shadowEvents)
	a.console("GET /api/shadow/events/{id}", permEventsRead, a.shadowEventDetail)
	a.console("GET /api/shadow/conversations", permEventsRead, a.shadowConversations)
	// The thread key is a query parameter, not a path segment: a conversation
	// identifier comes from the AI platform, is not a UUID, and can hold
	// characters a path would have to escape.
	a.console("GET /api/shadow/conversation", permEventsRead, a.shadowConversation)
	a.console("GET /api/shadow/cartography", permEventsRead, a.cartography)
	a.console("GET /api/shadow/filters", permEventsRead, a.savedShadowFilters)
	a.console("POST /api/shadow/filters", permEventsRead, a.saveShadowFilter)
	a.console("PUT /api/shadow/filters/{id}", permEventsRead, a.saveShadowFilter)
	a.console("DELETE /api/shadow/filters/{id}", permEventsRead, a.deleteShadowFilter)
	a.console("GET /api/shadow/export", permEventsRead, a.shadowExport)
	// Reading prompt content is `content.read`, held through a role like every other
	// permission (product decision, 2026-09-15); there is no longer a per-member grant to
	// register here.
	//
	// Purging has its own permission since 2026-09-21. It used to reuse `content.read`
	// on the reasoning that deleting retained text supposes the right to read it -- but
	// that made a READ permission the only role-level gate in front of an irreversible
	// mass DELETE, and it handed that power to every role that could merely consult a
	// prompt, the public demonstration instance's read-only role included. Fresh MFA and
	// the audit entry were the real protection, which is not what a permission name
	// should be for.
	//
	// sessionOnly like every other route behind requireFreshMFA (PUT /api/privacy,
	// reveal, erase, alias rotation): an API key has no second factor to present, so
	// letting it reach the handler only to be refused with `fresh_mfa_required` told
	// the caller to re-authenticate when the truth is "not available to keys" -- and
	// left the route one refactor of requireFreshMFA away from being key-reachable.
	a.sessionOnly("POST /api/shadow/content/purge", permContentPurge, a.purgeContent)
	a.console("GET /api/shadow/operations", permPolicyManage, a.shadowOperations)
	a.console("GET /api/shadow/metrics", permPolicyManage, a.shadowMetrics)
	a.mux.HandleFunc("POST /v2/enroll", a.enroll)
	a.mux.HandleFunc("GET /v2/policy", a.v2Policy)
	a.mux.HandleFunc("POST /v2/events", a.deviceFirst(a.v2Ingest))
	a.mux.HandleFunc("POST /v2/events/complete", a.deviceFirst(a.v2Complete))
	a.mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 404, map[string]string{"error": "not_found", "message": "Endpoint route not found."})
	})
}
