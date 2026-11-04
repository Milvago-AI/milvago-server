package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

func auditRegexSearchFilters(r *http.Request, tx pgx.Tx, view string, count int) error {
	q := r.URL.Query()
	selection := map[string][]string{}
	for _, key := range []string{"actor_id", "query"} {
		if !slices.Contains(q["regex"], key) {
			continue
		}
		values, err := shadowRegexValues(q[key])
		if err != nil {
			return err
		}
		slices.Sort(values)
		selection[key] = values
	}
	if !slices.Contains(q["regex"], "actor_id") && len(q["actor_id"]) > 0 {
		values, err := shadowFilterValues("actor_id", q["actor_id"])
		if err != nil {
			return err
		}
		slices.Sort(values)
		selection["literal_actor_id"] = values
	}
	p := privacyFor(r)
	if p == nil {
		return errors.New(msgPrivacyContextMissing)
	}
	encoded, err := json.Marshal(selection)
	if err != nil {
		return err
	}
	// A pattern may select several subjects, so audit one explicit search scope.
	// Never pass expressions to the literal subject validator or drop their audit.
	target := fmt.Sprintf("search:%x", hash(string(encoded)))
	s := p.session
	tag, err := tx.Exec(r.Context(), `INSERT INTO subject_views(organization_id,actor_id,subject,view,last_at) VALUES($1,$2,$3,$4,clock_timestamp()) ON CONFLICT(organization_id,actor_id,subject,view) DO UPDATE SET last_at=excluded.last_at WHERE subject_views.last_at<clock_timestamp()-interval '5 minutes'`, s.OrganizationID, s.UserID, target, view)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	return privacyAudit(r, tx, s, "subject.view", target, map[string]any{"view": view, "rows": count, "regex_search": selection})
}

func shadowRegexDLP(f *shadowFilter, q url.Values, patterns map[string]bool) error {
	terms := []string{}
	for _, key := range []string{"dlp_rule", "dlp_mode", "dlp_consequence", "dlp_outcome"} {
		value := q.Get(key)
		if value == "" {
			continue
		}
		if len(q[key]) != 1 || len(value) > 100 {
			return bad("Invalid DLP filter.")
		}
		field := map[string]string{"dlp_rule": "rule_id", "dlp_mode": "mode", "dlp_consequence": "consequence", "dlp_outcome": "outcome"}[key]
		op := "="
		if patterns[key] {
			if err := validateShadowRegex(value); err != nil {
				return err
			}
			op = "~*"
		} else {
			allowed := map[string][]string{
				"dlp_mode":        {"active", "simulation"},
				"dlp_consequence": {"observe", "warn", "block", "mask", "replace"},
				"dlp_outcome":     {"unavailable", "simulated", "blocked", "overridden", "prepared", "final_blocked", "observed", "cancelled", "observed_after_send", "matched"},
			}
			if (key == "dlp_rule" && !dlpIdentifier(value)) || (key != "dlp_rule" && !slices.Contains(allowed[key], value)) {
				return bad("Invalid DLP filter.")
			}
		}
		f.Args = append(f.Args, value)
		terms = append(terms, fmt.Sprintf("decision->>'%s' %s $%d", field, op, len(f.Args)))
		f.Criteria[key] = value
	}
	// All categories must match the same decision, including when literal and
	// regex criteria are mixed. Patterns and values never become SQL.
	f.Where += ` AND EXISTS(SELECT 1 FROM dlp_decisions dd CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(dd.decisions)='array' THEN dd.decisions ELSE '[]'::jsonb END) decision WHERE dd.organization_id=e.organization_id AND dd.device_id=e.device_id AND dd.event_id=e.id AND dd.expires_at>now() AND ` + strings.Join(terms, " AND ") + ")"
	return nil
}

func shadowGlobalRegexWhere(patternArg, namesArg int) string {
	// Search independently so anchors retain their field-level meaning.
	columns := []string{"e.provider", "e.tool", "e.model", "e.kind", "e.action", "e.source", "e.effort", "e.session", "e.url", "e.platform_id", "e.decision_reason", "e.conversation_id", "e.correlation_id", "e.device_id::text", "e.id::text", actorBucket, "d.hostname", "c.alias", osAliasSQL, "(CASE WHEN jsonb_array_length(e.files)>0 THEN 'yes' ELSE 'no' END)"}
	if Edition == "commercial" {
		columns = append(columns, "e.sensitivity")
	}
	terms := make([]string, 0, len(columns)+3)
	for _, col := range columns {
		terms = append(terms, fmt.Sprintf("%s ~* $%d", col, patternArg))
	}
	terms = append(terms, fmt.Sprintf("e.device_id = ANY($%d::uuid[])", namesArg))
	terms = append(terms, fmt.Sprintf("EXISTS(SELECT 1 FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(e.labels)='array' THEN e.labels ELSE '[]'::jsonb END) label WHERE label ~* $%d)", patternArg))
	terms = append(terms, fmt.Sprintf(`EXISTS(SELECT 1 FROM dlp_decisions dd CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(dd.decisions)='array' THEN dd.decisions ELSE '[]'::jsonb END) decision WHERE dd.organization_id=e.organization_id AND dd.device_id=e.device_id AND dd.event_id=e.id AND dd.expires_at>now() AND (decision->>'rule_id' ~* $%d OR decision->>'mode' ~* $%d OR decision->>'consequence' ~* $%d OR decision->>'outcome' ~* $%d))`, patternArg, patternArg, patternArg, patternArg))
	return " AND (" + strings.Join(terms, " OR ") + ")"
}

func (a *App) requestShadowFilter(r *http.Request, tx pgx.Tx, s *Session) (shadowFilter, error) {
	f, err := parseShadowFilter(r.URL.Query())
	if err != nil || (f.DeviceNameArg == 0 && f.QueryNameArg == 0) {
		return f, err
	}
	if err := requireIndividual(r); err != nil {
		return f, err
	}
	q := r.URL.Query()
	devicePatterns := []*regexp.Regexp{}
	for _, pattern := range q["device_name"] {
		if !slices.Contains(q["regex"], "device_name") {
			pattern = "^" + regexp.QuoteMeta(pattern) + "$"
		}
		compiled, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return f, invalidShadowRegex()
		}
		devicePatterns = append(devicePatterns, compiled)
	}
	var global *regexp.Regexp
	if f.QueryNameArg > 0 {
		global, err = regexp.Compile("(?i)" + q.Get("query"))
		if err != nil {
			return f, invalidShadowRegex()
		}
	}
	// Device names are encrypted at rest. Resolve the bounded tenant fleet once,
	// then keep the event query on device UUIDs; never decrypt every event.
	rows, err := tx.Query(r.Context(), "SELECT id::text,coalesce(hostname_ciphertext,'') FROM devices WHERE organization_id=$1 ORDER BY id LIMIT 10001", s.OrganizationID)
	if err != nil {
		return f, err
	}
	defer rows.Close()
	deviceIDs, globalIDs := []string{}, []string{}
	count := 0
	for rows.Next() {
		count++
		if count > 10000 {
			return f, apiError{413, "read_too_large", "Narrow the search scope."}
		}
		if err := r.Context().Err(); err != nil {
			return f, err
		}
		var id, cipher string
		if err := rows.Scan(&id, &cipher); err != nil {
			return f, err
		}
		name, err := a.machineName(r, s.OrganizationID, id, cipher)
		if err != nil {
			return f, err
		}
		if name == "" {
			continue
		}
		for _, pattern := range devicePatterns {
			if pattern.MatchString(name) {
				deviceIDs = append(deviceIDs, id)
				break
			}
		}
		if global != nil && global.MatchString(name) {
			globalIDs = append(globalIDs, id)
		}
	}
	if err := rows.Err(); err != nil {
		return f, err
	}
	if f.DeviceNameArg > 0 {
		f.Args[f.DeviceNameArg-1] = deviceIDs
	}
	if f.QueryNameArg > 0 {
		f.Args[f.QueryNameArg-1] = globalIDs
	}
	return f, nil
}
