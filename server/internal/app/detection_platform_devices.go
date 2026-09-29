package app

import (
	"net/http"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// knownPlatformDevices names the machines that reached one known platform.
//
// Both editions :
// Discovery answers "who went there", and a count alone leaves an administrator with
// nothing to act on. The gates are those of the candidate-domain drill-down:
//
//  1. Aggregate-only reporting refuses outright. That mode exists so that no screen
//     names a machine behind a count; answering here would be the one door left open.
//  2. The platform must be one Discovery itself shows: neither silenced nor already
//     captured in full by this edition. Otherwise the route reads "which of my
//     machines reached <any host>", reachable by typing a URL.
//  3. The machine name comes from machineName, like every other screen, so
//     `?identity=aliases` still answers aliases and the name stays sealed at rest.
//
// The records are presence events, so the machine is on the row itself and the count
// is a number of visits. Their window is the organization's own event retention; the
// answer carries it so the console can say which period it is talking about.
//
// What is NOT answered here: the OS account behind a visit. It stays behind the reveal
// of the conversations view; naming a machine is inventory, naming a person is not.
func (a *App) knownPlatformDevices(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	host := r.PathValue("provider")
	if len(host) > 253 || !domainPattern.MatchString(host) {
		return bad("Invalid platform host.")
	}
	p, e := a.readPrivacy(r.Context(), tx, s.OrganizationID)
	if e != nil {
		return e
	}
	if p.Config.AggregateOnly {
		return apiError{403, "aggregate_only", "Aggregate-only reporting is configured: this organization's records never name a machine."}
	}
	hidden, covered, e := discoveryExclusions(r.Context(), tx)
	if e != nil {
		return e
	}
	// A platform this organization silenced, or one this edition captures in full, is
	// not on the screen; answering for it here would walk around the screen.
	if slices.Contains(hidden, host) || slices.Contains(covered, host) {
		return apiError{404, "platform_not_found", "This platform is not listed by discovery for this organization."}
	}
	var retention int
	if e = tx.QueryRow(r.Context(), `SELECT retention_days FROM settings WHERE organization_id=$1`, s.OrganizationID).Scan(&retention); e != nil {
		return e
	}
	rows, e := tx.Query(r.Context(), `SELECT e.device_id,d.hostname_ciphertext,count(*) AS visits,max(e.occurred_at) AS last_seen
 FROM shadow_events e
 JOIN devices d ON d.id=e.device_id
 WHERE e.detector='presence' AND e.provider=$1
 GROUP BY e.device_id,d.hostname_ciphertext
 ORDER BY visits DESC,last_seen DESC
 LIMIT 200`, host)
	if e != nil {
		return e
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, cipher string
		var visits int64
		var lastSeen time.Time
		if e = rows.Scan(&id, &cipher, &visits, &lastSeen); e != nil {
			return e
		}
		name, e := a.machineName(r, s.OrganizationID, id, cipher)
		if e != nil {
			return e
		}
		items = append(items, map[string]any{"device_id": id, "hostname": name, "observations": visits, "last_seen": lastSeen})
	}
	if e = rows.Err(); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"items": items, "window_days": retention})
	return nil
}
