package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

var inventorySearchFields = []string{"app", "service", "device", "vendor", "type", "environment", "source", "state", "query"}

type inventorySearch struct {
	values   map[string][]string
	regex    map[string]bool
	compiled map[string][]*regexp.Regexp
}

// Accept only the documented schema. No field, pattern or cursor is SQL text.
func parseInventorySearch(q url.Values) (inventorySearch, error) {
	f := inventorySearch{values: map[string][]string{}, regex: map[string]bool{}, compiled: map[string][]*regexp.Regexp{}}
	if len(q.Encode()) > 6200 {
		return f, bad("Search exceeds its limit.")
	}
	for key, values := range q {
		switch key {
		case "limit", "cursor", "identity":
			if len(values) != 1 {
				return f, bad("Invalid inventory query.")
			}
		case "regex":
			if len(values) > len(inventorySearchFields) {
				return f, bad("Invalid regex fields.")
			}
			for _, field := range values {
				if !slices.Contains(inventorySearchFields, field) || f.regex[field] {
					return f, bad("Invalid regex field.")
				}
				f.regex[field] = true
			}
		default:
			if !slices.Contains(inventorySearchFields, key) || len(values) > 20 || (key == "query" && len(values) != 1) {
				return f, bad("Invalid inventory field.")
			}
			f.values[key] = values
		}
	}
	for _, key := range inventorySearchFields {
		for _, value := range f.values[key] {
			if len(value) > 200 || (key == "query" && len(value) > 100) || strings.TrimSpace(value) == "" {
				return f, bad("Invalid inventory value.")
			}
			pattern := value
			if !f.regex[key] {
				pattern = regexp.QuoteMeta(value)
			}
			if err := validateShadowRegex(pattern); err != nil {
				return f, err
			}
			if !f.regex[key] {
				pattern = "^" + pattern + "$"
			}
			compiled, err := regexp.Compile("(?i)" + pattern)
			if err != nil {
				return f, invalidShadowRegex()
			}
			f.compiled[key] = append(f.compiled[key], compiled)
		}
		if f.regex[key] && len(f.values[key]) == 0 {
			return f, bad("Regex field has no value.")
		}
	}
	return f, nil
}

func (f inventorySearch) matches(key, value string) bool {
	for _, compiled := range f.compiled[key] {
		if compiled.MatchString(value) {
			return true
		}
	}
	return false
}

// Resolve encrypted names once per tenant, never per observation. A device
// predicate and environment details require devices.read. Web service metadata
// retains policy.manage; unqualified search skips protected local details.
func (a *App) inventorySearchNames(r *http.Request, tx pgx.Tx, s *Session, f inventorySearch) ([]string, []string, error) {
	explicit, global := []string{}, []string{}
	if !hasPermission(s.Permissions, permDevicesRead) {
		if len(f.values["device"]) > 0 || len(f.values["environment"]) > 0 || (len(f.values["service"]) > 0 && !hasPermission(s.Permissions, permPolicyManage)) {
			return nil, nil, forbidden()
		}
		return explicit, global, nil
	}
	if len(f.values["device"]) == 0 && len(f.values["query"]) == 0 {
		return explicit, global, nil
	}
	rows, err := tx.Query(r.Context(), "SELECT id::text,coalesce(hostname_ciphertext,'') FROM devices WHERE organization_id=$1 ORDER BY id LIMIT 10001", s.OrganizationID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > 10000 {
			return nil, nil, apiError{413, "read_too_large", "Narrow the search scope."}
		}
		if err := r.Context().Err(); err != nil {
			return nil, nil, err
		}
		var id, cipher string
		if err := rows.Scan(&id, &cipher); err != nil {
			return nil, nil, err
		}
		name, err := a.machineName(r, s.OrganizationID, id, cipher)
		if err != nil {
			return nil, nil, err
		}
		if name != "" && f.matches("device", name) {
			explicit = append(explicit, id)
		}
		if name != "" && f.matches("query", name) {
			global = append(global, id)
		}
	}
	return explicit, global, rows.Err()
}

type inventoryMetadata struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Vendor string `json:"vendor"`
}

func inventoryApplicationMetadata(raw json.RawMessage, native []inventoryMetadata) ([]byte, error) {
	var catalog struct {
		Signatures []struct {
			ApplicationID string `json:"application_id"`
			Name          string `json:"name"`
			Vendor        string `json:"vendor"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &catalog); err != nil {
		return nil, err
	}
	entries := map[string]inventoryMetadata{}
	for _, entry := range native {
		entries[entry.ID] = entry
	}
	for _, sig := range catalog.Signatures {
		if entry, ok := entries[sig.ApplicationID]; !ok || entry.Name == "" {
			entries[sig.ApplicationID] = inventoryMetadata{sig.ApplicationID, sig.Name, sig.Vendor}
		}
	}
	// Keyed lookup avoids a rowset catalogue join whose estimated selectivity
	// could cause a full catalogue scan for each matched observation.
	return json.Marshal(entries)
}

// Each predicate applies to one observation before aggregation and pagination.
// Only inventory metadata is selected, never message bodies or account names.
const inventoryLocalRows = `SELECT 'application'::text family,i.application_id id,
 coalesce(nullif($2::jsonb->i.application_id->>'name',''),i.application_id) name,coalesce($2::jsonb->i.application_id->>'vendor','') vendor,'software'::text type,
 i.device_id,i.device_id::text||'/'||i.scope||'/'||i.entity_id object_key,
 CASE WHEN $5::boolean THEN ARRAY(SELECT c.provider FROM discovery_communications c WHERE c.organization_id=i.organization_id AND c.device_id=i.device_id AND c.scope=i.scope AND c.entity_id=i.entity_id AND c.expires_at>now()) ELSE ARRAY[]::text[] END services,
 CASE WHEN $5::boolean THEN array_remove(ARRAY[i.scope,e.kind,e.display->>'name',e.display->>'image'],NULL) ELSE ARRAY[]::text[] END environments,
 ARRAY['discovery',i.signature_id]||ARRAY(SELECT proof->>'source' FROM jsonb_array_elements(CASE WHEN jsonb_typeof(i.evidence)='array' THEN i.evidence ELSE '[]'::jsonb END) proof WHERE proof->>'source' IS NOT NULL) sources,
 i.state,1::bigint observations,i.first_seen,i.last_seen,coalesce(r.status,'review') status,true attributed,NULL::text account,false blocked
 FROM discovery_identifications i LEFT JOIN discovery_entities e ON e.organization_id=i.organization_id AND e.device_id=i.device_id AND e.scope=i.scope AND e.id=i.entity_id AND e.expires_at>now()
 LEFT JOIN discovery_reviews r ON r.organization_id=i.organization_id AND r.application_id=i.application_id
 WHERE i.organization_id=$1 AND i.expires_at>now()`

const inventoryEmptyRows = `SELECT ''::text family,''::text id,''::text name,''::text vendor,''::text type,
 NULL::uuid device_id,''::text object_key,ARRAY[]::text[] services,ARRAY[]::text[] environments,ARRAY[]::text[] sources,
 ''::text state,0::bigint observations,NULL::timestamptz first_seen,NULL::timestamptz last_seen,''::text status,false attributed,NULL::text account,false blocked WHERE false`

const inventoryPlatformRows = `SELECT 'platform'::text family,e.provider id,coalesce(nullif($2::jsonb->e.provider->>'name',''),e.provider) name,''::text vendor,'web'::text type,
 e.device_id,e.id::text object_key,ARRAY[e.provider] services,ARRAY['browser']::text[] environments,ARRAY['presence']::text[] sources,
 'presence'::text state,1::bigint observations,e.occurred_at first_seen,e.occurred_at last_seen,''::text status,true attributed,e.user_key::text account,(e.action='blocked') blocked
 FROM shadow_events e WHERE e.organization_id=$1 AND e.detector='presence' AND e.occurred_at>now()-make_interval(days=>$4)
 AND e.provider<>ALL($3::text[])`

const inventoryCandidateRows = `SELECT 'candidate'::text family,c.domain id,c.domain name,''::text vendor,'web'::text type,
 NULL::uuid device_id,c.domain object_key,ARRAY[c.domain] services,ARRAY['browser']::text[] environments,ARRAY['candidate']::text[] sources,
 c.status state,c.count::bigint observations,c.first_seen,c.last_seen,c.status,false attributed,NULL::text account,false blocked
 FROM candidate_domains c WHERE c.organization_id=$1 AND c.domain<>ALL($3::text[])`

// Match individual fields before expanding optional observation arrays. Building
// one combined array forced every correlated provider/evidence projection for
// every row, even when a scalar field had already matched.
func inventoryMatchAny(columns, arrays []string, op string, argument int) string {
	terms := []string{}
	for _, column := range columns {
		terms = append(terms, fmt.Sprintf("%s %s ANY($%d::text[])", column, op, argument))
	}
	for _, column := range arrays {
		terms = append(terms, fmt.Sprintf("EXISTS(SELECT 1 FROM unnest(%s) value WHERE value %s ANY($%d::text[]))", column, op, argument))
	}
	return "(" + strings.Join(terms, " OR ") + ")"
}

func (f inventorySearch) where(args *[]any, devices, global []string) string {
	columns := map[string][]string{
		"app": {"o.id", "o.name"}, "vendor": {"o.vendor"},
		"type": {"o.type"}, "state": {"o.state", "o.status"},
	}
	arrays := map[string][]string{
		"service": {"o.services"}, "environment": {"o.environments"}, "source": {"o.sources"},
	}
	terms := []string{"true"}
	for _, key := range inventorySearchFields {
		values := f.values[key]
		if len(values) == 0 {
			continue
		}
		if key == "device" {
			*args = append(*args, devices)
			terms = append(terms, fmt.Sprintf("o.device_id=ANY($%d::uuid[])", len(*args)))
			continue
		}
		*args = append(*args, values)
		valueArg := len(*args)
		op := "="
		if f.regex[key] {
			op = "~*"
		}
		if key == "query" {
			*args = append(*args, global)
			match := inventoryMatchAny([]string{"o.id", "o.name", "o.vendor", "o.type", "o.state", "o.status"}, []string{"o.services", "o.environments", "o.sources"}, op, valueArg)
			terms = append(terms, fmt.Sprintf("(o.device_id=ANY($%d::uuid[]) OR %s)", len(*args), match))
		} else {
			terms = append(terms, inventoryMatchAny(columns[key], arrays[key], op, valueArg))
		}
	}
	return strings.Join(terms, " AND ")
}

func (a *App) inventorySearch(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	local := hasPermission(s.Permissions, permDiscoveryRead)
	web := hasPermission(s.Permissions, permPolicyManage)
	native := discoveryInventoryVisible(s)
	if !local && !web && !native {
		return forbidden()
	}
	if err := requireIndividual(r); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(r.Context(), regexReadBudget)
	defer cancel()
	r = r.WithContext(ctx)
	// JIT setup dominated these bounded interactive reads on the runner. Keep
	// both settings local to this request's transaction, including on rollback.
	if _, err := tx.Exec(ctx, "SELECT set_config('statement_timeout','5s',true),set_config('jit','off',true)"); err != nil {
		return err
	}
	f, err := parseInventorySearch(r.URL.Query())
	if err != nil {
		return err
	}
	pageRequest := r.Clone(ctx)
	pageURL := *r.URL
	pageQuery := r.URL.Query()
	pageQuery.Del("cursor")
	pageURL.RawQuery = pageQuery.Encode()
	pageRequest.URL = &pageURL
	limit, _, err := discoveryPage(pageRequest)
	if err != nil {
		return err
	}
	afterFamily, afterID := "", ""
	cursor := []string{}
	if encoded := r.URL.Query().Get("cursor"); encoded != "" {
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if len(encoded) > 1024 || err != nil || json.Unmarshal(raw, &cursor) != nil {
			return bad("Invalid inventory cursor.")
		}
		if len(cursor) == 0 {
			return bad("Invalid inventory cursor.")
		}
	}
	if len(cursor) > 0 {
		if len(cursor) != 2 || !slices.Contains([]string{"application", "candidate", "platform"}, cursor[0]) || len(cursor[1]) == 0 || len(cursor[1]) > 253 {
			return bad("Invalid inventory cursor.")
		}
		afterFamily, afterID = cursor[0], cursor[1]
	}
	devices, global, err := a.inventorySearchNames(r, tx, s, f)
	if err != nil {
		return err
	}
	raw := json.RawMessage(`{"signatures":[]}`)
	if local {
		raw, err = currentDiscoveryCatalog(ctx, tx, s.OrganizationID)
		if err != nil {
			return err
		}
	}
	nativeMetadata := inventoryNativeMetadata(s)
	var webCatalog DetectionContent
	hidden := []string{}
	retention := 30
	if web {
		muted, covered, err := discoveryExclusions(ctx, tx)
		if err != nil {
			return err
		}
		hidden = append(muted, covered...)
		_, _, webCatalog, err = currentDetection(ctx, tx)
		if err != nil {
			return err
		}
		for _, platform := range webCatalog.KnownPlatforms {
			for _, domain := range platform.Domains {
				nativeMetadata = append(nativeMetadata, inventoryMetadata{domain, platform.Label, ""})
			}
		}
		if err := tx.QueryRow(ctx, "SELECT retention_days FROM settings WHERE organization_id=$1", s.OrganizationID).Scan(&retention); err != nil {
			return err
		}
	}
	metadata, err := inventoryApplicationMetadata(raw, nativeMetadata)
	if err != nil {
		return err
	}
	sources := []string{inventoryEmptyRows}
	if local {
		sources = append(sources, inventoryLocalRows)
	}
	if native {
		sources = append(sources, inventoryNativeRows())
	}
	if web {
		sources = append(sources, inventoryPlatformRows, inventoryCandidateSearchRows())
	}
	localDetails := hasPermission(s.Permissions, permDevicesRead) && r.URL.Query().Get("identity") != "aliases"
	args := []any{s.OrganizationID, metadata, hidden, retention, localDetails}
	where := f.where(&args, devices, global)
	args = append(args, afterFamily, afterID, limit)
	familyArg, idArg, limitArg := len(args)-2, len(args)-1, len(args)
	query := `WITH parameters AS (SELECT $2::jsonb metadata,$3::text[] hidden,$4::int retention,$5::boolean device_details),
 observations AS (` + strings.Join(sources, " UNION ALL ") + `),
 matched AS MATERIALIZED (SELECT family,id,name,vendor,type,device_id,object_key,attributed,account,blocked,state,status,first_seen,last_seen,observations FROM observations o WHERE ` + where + `),
 matching_keys AS MATERIALIZED (SELECT DISTINCT family,id FROM matched),
 page_keys AS MATERIALIZED (SELECT family,id FROM matching_keys WHERE (family,id)>($` + fmt.Sprint(familyArg) + `,$` + fmt.Sprint(idArg) + `) ORDER BY family,id LIMIT $` + fmt.Sprint(limitArg) + `),
 applications AS (
 SELECT family,id,max(name) name,max(vendor) vendor,max(type) type,
 CASE WHEN bool_or(attributed) THEN count(DISTINCT device_id) ELSE NULL END devices,
 count(DISTINCT object_key) instances,sum(observations) observations,count(DISTINCT account) accounts,count(*) FILTER(WHERE blocked) blocked,
 array_agg(DISTINCT state ORDER BY state) states,max(status) status,min(first_seen) first_seen,max(last_seen) last_seen
 FROM matched JOIN page_keys USING(family,id) GROUP BY family,id),
 page AS (SELECT * FROM applications)
 SELECT jsonb_build_object('items',coalesce((SELECT jsonb_agg(to_jsonb(p) ORDER BY family,id) FROM page p),'[]'::jsonb),
 'total',(SELECT count(*) FROM matching_keys),
 'has_more',(SELECT count(*) FROM matching_keys WHERE (family,id)>($` + fmt.Sprint(familyArg) + `,$` + fmt.Sprint(idArg) + `))>$` + fmt.Sprint(limitArg) + `)`
	var out struct {
		Items   []map[string]any `json:"items"`
		Total   int64            `json:"total"`
		HasMore bool             `json:"has_more"`
	}
	var result []byte
	if err := tx.QueryRow(ctx, query, args...).Scan(&result); err != nil {
		return err
	}
	if err := json.Unmarshal(result, &out); err != nil {
		return err
	}
	for _, item := range out.Items {
		if item["family"] == "candidate" {
			domain, _ := item["id"].(string)
			item["promotable"] = candidateInCatalog(webCatalog, domain)
		}
	}
	next := ""
	if out.HasMore && len(out.Items) > 0 {
		last := out.Items[len(out.Items)-1]
		next = discoveryCursor(last["family"].(string), last["id"].(string))
	}
	reply(w, 200, map[string]any{"items": out.Items, "total": out.Total, "next_cursor": next, "discovery": local, "web": web, "native": native, "discovery_enabled": privacyFor(r).view.Config.DiscoveryEnabled})
	return nil
}
