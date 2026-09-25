package app

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"net/http"
	"time"
)

func weekStart(t time.Time) time.Time {
	t = t.UTC()
	d := (int(t.Weekday()) + 6) % 7
	return time.Date(t.Year(), t.Month(), t.Day()-d, 0, 0, 0, 0, time.UTC)
}
func (a *App) buildAggregateReports(ctx context.Context, tx pgx.Tx, org string, now time.Time) error {
	p, e := a.readPrivacy(ctx, tx, org)
	if e != nil {
		return e
	}
	var days int
	var created time.Time
	if e = tx.QueryRow(ctx, "SELECT s.retention_days,p.created_at FROM settings s JOIN privacy_settings p ON p.organization_id=s.organization_id WHERE s.organization_id=$1", org).Scan(&days, &created); e != nil {
		return e
	}
	// A complete week and its late-arrival allowance must exist. Partial weeks
	// are never represented as complete by looking only at the rows that survived.
	if min(days, p.Config.IdentityDays) < 8 {
		return nil
	}
	last := weekStart(now.Add(-24*time.Hour)).AddDate(0, 0, -7)
	first := weekStart(now.AddDate(0, 0, -min(days, p.Config.IdentityDays)))
	for start := first; !start.After(last); start = start.AddDate(0, 0, 7) {
		end := start.AddDate(0, 0, 7)
		if start.Before(created) || start.Before(now.AddDate(0, 0, -min(days, p.Config.IdentityDays))) {
			continue
		}
		var exists bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM aggregate_reports WHERE week_start=$1)", start).Scan(&exists); e != nil {
			return e
		}
		if exists {
			continue
		}
		var raw []byte
		// Only the disjoint published cells are retained. Neither a grand total nor
		// suppressed labels/counts can reveal a hidden cell by subtraction.
		//
		// Two breakdowns of the same week travel together: by team (the OIDC claim on
		// the person) and by device group (Fleet > Groups). The group is read at build
		// time and its name is frozen into the published report: a later rename, or a
		// device moved to another group, never rewrites a week already published.
		//
		// They partition the *same* events, so for one (tool,provider,model) the team
		// totals and the group totals are equal by construction. Publishing both as they
		// come would reconstruct a withheld cell exactly by subtraction: where that
		// triple is complete on one side and one cell is withheld on the other, the
		// difference is the withheld count -- k respected cell by cell, broken across the
		// pair. So a triple that falls under k on either side is `tainted`, and every
		// cell carrying it is withheld on both sides. This is stricter than a per-cell
		// threshold, deliberately: a cell that clears k on its own is still withheld when
		// its sibling on the other breakdown does not.
		//
		// Each side keeps its own suppression flag -- one shared flag would call a
		// breakdown complete because the other one is -- and each is raised by comparing
		// counts, so a cell withheld only by tainting still raises it. Neither those
		// counts nor the withheld labels leave this query.
		e = tx.QueryRow(ctx, `WITH grouped AS (
   SELECT coalesce(nullif(c.team,''),'unassigned') team,e.tool,e.provider,e.model,
    count(*) FILTER(WHERE e.kind='prompt') prompts,
    count(*) FILTER(WHERE e.kind='response') responses,count(DISTINCT e.collaborator_id) subjects
   FROM shadow_events e JOIN collaborators c ON c.organization_id=e.organization_id AND c.id=e.collaborator_id
   WHERE e.occurred_at >= $1 AND e.occurred_at < $2
   GROUP BY 1,2,3,4
  ), by_group AS (
   SELECT coalesce(nullif(g.name,''),'unassigned') "group",e.tool,e.provider,e.model,
    count(*) FILTER(WHERE e.kind='prompt') prompts,
    count(*) FILTER(WHERE e.kind='response') responses,count(DISTINCT e.collaborator_id) subjects
   FROM shadow_events e JOIN collaborators c ON c.organization_id=e.organization_id AND c.id=e.collaborator_id
    JOIN devices d ON d.organization_id=e.organization_id AND d.id=e.device_id
    LEFT JOIN device_groups g ON g.organization_id=d.organization_id AND g.id=d.group_id
   WHERE e.occurred_at >= $1 AND e.occurred_at < $2
   GROUP BY 1,2,3,4
  ), tainted AS (
   SELECT tool,provider,model FROM grouped WHERE subjects<$3
   UNION SELECT tool,provider,model FROM by_group WHERE subjects<$3
  ), publishable AS (
   SELECT g.* FROM grouped g WHERE g.subjects>=$3
    AND NOT EXISTS(SELECT 1 FROM tainted t WHERE t.tool=g.tool AND t.provider=g.provider AND t.model=g.model)
  ), group_publishable AS (
   SELECT g.* FROM by_group g WHERE g.subjects>=$3
    AND NOT EXISTS(SELECT 1 FROM tainted t WHERE t.tool=g.tool AND t.provider=g.provider AND t.model=g.model)
  )
  SELECT jsonb_build_object('cells',coalesce((SELECT jsonb_agg(x ORDER BY team,tool,provider,model) FROM publishable x),'[]'),
   'suppressed',(SELECT count(*) FROM grouped)>(SELECT count(*) FROM publishable) OR EXISTS(SELECT 1 FROM shadow_events WHERE occurred_at>=$1 AND occurred_at<$2 AND collaborator_id IS NULL),
   'group_cells',coalesce((SELECT jsonb_agg(x ORDER BY x."group",x.tool,x.provider,x.model) FROM group_publishable x),'[]'),
   'group_suppressed',(SELECT count(*) FROM by_group)>(SELECT count(*) FROM group_publishable) OR EXISTS(SELECT 1 FROM shadow_events WHERE occurred_at>=$1 AND occurred_at<$2 AND collaborator_id IS NULL))`, start, end, p.Config.K).Scan(&raw)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO aggregate_reports(organization_id,week_start,configuration_revision,k,report,expires_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, org, start, p.Revision, p.Config.K, raw, end.AddDate(0, 0, days)); e != nil {
			return e
		}
	}
	return nil
}
func (a *App) aggregateReports(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	// No ad hoc intersections, rolling periods, or individual filters.
	for k := range r.URL.Query() {
		if k != "week" {
			return bad("Reports accept only a complete week selection.")
		}
	}
	week := r.URL.Query().Get("week")
	if week != "" {
		d, e := time.Parse("2006-01-02", week)
		if e != nil || !d.Equal(weekStart(d)) {
			return bad("Week must be a Monday in YYYY-MM-DD format.")
		}
	}
	p, e := a.readPrivacy(r.Context(), tx, s.OrganizationID)
	if e != nil {
		return e
	}
	rows, e := tx.Query(r.Context(), `SELECT week_start::text,k,report FROM aggregate_reports WHERE expires_at>now() AND ($1='' OR week_start::text=$1) AND k >= $2 ORDER BY week_start DESC LIMIT 53`, week, p.Config.K)
	if e != nil {
		return e
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var date string
		var k int
		var report json.RawMessage
		if e = rows.Scan(&date, &k, &report); e != nil {
			return e
		}
		items = append(items, map[string]any{"week_start": date, "k": k, "report": report, "coverage": "complete"})
	}
	if e = rows.Err(); e != nil {
		return e
	}
	// Which breakdowns this organization can actually read, as two booleans and
	// nothing else: no claim name, no value, no count. Both ask whether the thing was
	// observed, not merely configured -- a claim the identity provider never serves and
	// a group holding no device both leave every row "unassigned", which teaches
	// nothing. A device carries a group only if that group exists, so the assignment is
	// the stronger question of the two.
	var teams, groups bool
	if e = tx.QueryRow(r.Context(), `SELECT $1::text<>'' AND EXISTS(SELECT 1 FROM collaborators WHERE team<>''),EXISTS(SELECT 1 FROM devices WHERE group_id IS NOT NULL)`, p.Config.TeamClaim).Scan(&teams, &groups); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"items": items, "k": p.Config.K, "coverage": map[bool]string{true: "complete", false: "insufficient_data"}[len(items) > 0], "teams_available": teams, "groups_available": groups})
	return nil
}
func (a *App) maintainPrivacy(ctx context.Context, tx pgx.Tx, org string, now time.Time) error {
	if e := a.buildAggregateReports(ctx, tx, org, now); e != nil {
		return e
	}
	p, e := a.readPrivacy(ctx, tx, org)
	if e != nil {
		return e
	}
	var days int
	if e = tx.QueryRow(ctx, "SELECT retention_days FROM settings WHERE organization_id=$1", org).Scan(&days); e != nil {
		return e
	}
	counts := map[string]int64{}
	cutoff := now.AddDate(0, 0, -min(days, p.Config.IdentityDays))
	queries := []struct {
		name, sql string
		args      []any
	}{
		{"content", "DELETE FROM shadow_content WHERE expires_at<$1", []any{now}},
		{"associations", "DELETE FROM device_collaborators WHERE expires_at<$1", []any{now}},
		{"events", "DELETE FROM shadow_events WHERE occurred_at<$1", []any{cutoff}},
		{"legacy_events", "DELETE FROM events WHERE occurred_at<$1", []any{cutoff}},
		{"subjects", `DELETE FROM collaborators c WHERE last_associated_at<$1 AND NOT EXISTS(SELECT 1 FROM shadow_events e WHERE e.collaborator_id=c.id) AND NOT EXISTS(SELECT 1 FROM device_collaborators d WHERE d.collaborator_id=c.id)`, []any{now.AddDate(0, 0, -p.Config.IdentityDays)}},
		{"reports", "DELETE FROM aggregate_reports WHERE expires_at<$1", []any{now}},
		{"detector_health", "DELETE FROM detector_health WHERE received_at<$1", []any{now.AddDate(0, 0, -30)}},
		{"candidates", "DELETE FROM candidate_domains WHERE last_seen<$1 AND status='new'", []any{now.AddDate(0, 0, -30)}},
		{"reveals", "DELETE FROM identity_reveals WHERE expires_at<$1", []any{now}},
		// Held and failed sensitive audits stay visible for thirty days, then leave with
		// this counted purge; the local audit row itself keeps its own retention.
		{"sensitive_outbox", "DELETE FROM privacy_audit_outbox WHERE state IN ('held','failed') AND updated_at<$1", []any{now.AddDate(0, 0, -30)}},
		{"consultation_dedupe", "DELETE FROM subject_views WHERE last_at<$1", []any{now.Add(-10 * time.Minute)}},
	}
	total := int64(0)
	for _, q := range queries {
		tag, e := tx.Exec(ctx, q.sql, q.args...)
		if e != nil {
			return e
		}
		if tag.RowsAffected() > 0 {
			counts[q.name] = tag.RowsAffected()
			total += tag.RowsAffected()
		}
	}
	if total > 0 {
		raw, _ := json.Marshal(counts)
		_, e = tx.Exec(ctx, `INSERT INTO audit(organization_id,actor,action,target,details) VALUES($1,'system','retention.purge','organization',$2)`, org, raw)
	}
	return e
}
