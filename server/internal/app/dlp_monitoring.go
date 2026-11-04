package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

type DLPDecisionView struct {
	ID          string        `json:"id"`
	OccurredAt  time.Time     `json:"occurred_at"`
	Channel     string        `json:"channel"`
	Fingerprint string        `json:"policy_fingerprint"`
	DeviceID    *string       `json:"device_id,omitempty"`
	EventID     *string       `json:"event_id,omitempty"`
	Action      string        `json:"action"`
	Delivery    string        `json:"delivery"`
	Decisions   []DLPDecision `json:"decisions"`
}

func (a *App) dlpDecisions(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := requireIndividual(r); err != nil {
		return err
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			return bad("Choose a DLP page size from 1 to 100.")
		}
		limit = value
	}
	args := []any{}
	where := `expires_at>clock_timestamp() AND channel IN ('browser','native')`
	add := func(sql string, value any) {
		args = append(args, value)
		where += " AND " + fmt.Sprintf(sql, len(args))
	}
	for _, key := range []string{"device_id", "event_id"} {
		if value := r.URL.Query().Get(key); value != "" {
			if !uuidPattern.MatchString(value) {
				return bad("Invalid DLP event identity.")
			}
			add(key+"=$%d", value)
		}
	}
	if channel := r.URL.Query().Get("channel"); channel != "" {
		if !slices.Contains([]string{"browser", "native"}, channel) {
			return bad("Invalid DLP channel.")
		}
		add("channel=$%d", channel)
	}
	if action := r.URL.Query().Get("action"); action != "" {
		if !slices.Contains([]string{"observe", "block", "transform", "review"}, action) {
			return bad("Invalid DLP action.")
		}
		add("action=$%d", action)
	}
	if delivery := r.URL.Query().Get("delivery"); delivery != "" {
		if !slices.Contains(dlpDeliveries, delivery) {
			return bad("Invalid DLP delivery state.")
		}
		add("delivery=$%d", delivery)
	}
	decisionFilter := map[string]string{}
	for _, key := range []string{"rule_id", "mode", "consequence", "outcome"} {
		if value := r.URL.Query().Get(key); value != "" {
			if len(value) > 100 {
				return bad("Invalid DLP filter.")
			}
			if key == "mode" && !slices.Contains([]string{"simulation", "active"}, value) {
				return bad("Invalid DLP mode.")
			}
			if key == "consequence" && !slices.Contains([]string{"observe", "warn", "block", "mask", "replace"}, value) {
				return bad("Invalid DLP consequence.")
			}
			if key == "outcome" && !slices.Contains(dlpDecisionOutcomes, value) {
				return bad("Invalid DLP outcome.")
			}
			decisionFilter[key] = value
		}
	}
	if len(decisionFilter) > 0 {
		add("decisions @> $%d::jsonb", dlpJSON([]map[string]string{decisionFilter}))
	}
	if cursor := r.URL.Query().Get("before"); cursor != "" {
		if len(cursor) > 256 {
			return bad("Invalid DLP cursor.")
		}
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		var page struct {
			At time.Time `json:"at"`
			ID string    `json:"id"`
		}
		if err != nil || json.Unmarshal(raw, &page) != nil || page.At.IsZero() || !uuidPattern.MatchString(page.ID) {
			return bad("Invalid DLP cursor.")
		}
		args = append(args, page.At, page.ID)
		where += fmt.Sprintf(" AND (occurred_at,id)<($%d,$%d::uuid)", len(args)-1, len(args))
	}
	args = append(args, limit+1)
	rows, err := tx.Query(r.Context(), `SELECT id,occurred_at,channel,policy_fingerprint,device_id,event_id,action,delivery,decisions FROM dlp_decisions WHERE `+where+fmt.Sprintf(` ORDER BY occurred_at DESC,id DESC LIMIT $%d`, len(args)), args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []DLPDecisionView{}
	for rows.Next() {
		var item DLPDecisionView
		var raw []byte
		if err = rows.Scan(&item.ID, &item.OccurredAt, &item.Channel, &item.Fingerprint, &item.DeviceID, &item.EventID, &item.Action, &item.Delivery, &raw); err != nil {
			return err
		}
		if json.Unmarshal(raw, &item.Decisions) != nil {
			return fmt.Errorf("stored DLP decision is invalid")
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		next = base64.RawURLEncoding.EncodeToString(dlpJSON(map[string]any{"at": items[len(items)-1].OccurredAt, "id": items[len(items)-1].ID}))
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next})
	return nil
}

type dlpDeviceStatus struct {
	DeviceID   string     `json:"device_id"`
	Hostname   string     `json:"hostname,omitempty"`
	Channel    string     `json:"channel"`
	Tool       string     `json:"tool"`
	Mechanism  string     `json:"mechanism"`
	Expected   string     `json:"expected_fingerprint"`
	Applied    string     `json:"applied_fingerprint"`
	Status     string     `json:"status"`
	ReportedAt *time.Time `json:"reported_at"`
}

func (a *App) dlpStatus(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	r = r.WithContext(dlpReadPageContext(r.Context()))
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = "endpoint"
	}
	if domain != "endpoint" {
		return bad("Invalid DLP domain.")
	}
	var now time.Time
	if err := tx.QueryRow(r.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	aggregate := privacyFor(r) != nil && privacyFor(r).view.Config.AggregateOnly
	cursor := r.URL.Query().Get("after")
	if len(cursor) > 256 {
		return bad("Invalid deployment cursor.")
	}
	if cursor != "" && aggregate {
		var err error
		cursor, err = a.openIdentity(s.OrganizationID, "dlp-status-cursor", cursor)
		if err != nil {
			return bad("Invalid deployment cursor.")
		}
	}
	if cursor != "" && !uuidPattern.MatchString(cursor) {
		return bad("Invalid deployment cursor.")
	}
	if cursor == "" {
		cursor = "00000000-0000-0000-0000-000000000000"
	}
	var device, group any
	for key, destination := range map[string]*any{"device_id": &device, "group_id": &group} {
		if value := r.URL.Query().Get(key); value != "" {
			if !uuidPattern.MatchString(value) {
				return bad("Invalid deployment scope.")
			}
			*destination = value
		}
	}
	rows, err := tx.Query(r.Context(), `WITH page AS (SELECT id,kind,capabilities,hostname_ciphertext,group_id FROM devices WHERE status<>'revoked' AND id>$1::uuid AND ($2::uuid IS NULL OR id=$2) AND ($3::uuid IS NULL OR group_id=$3) ORDER BY id LIMIT 101)
      SELECT d.id,d.kind,d.capabilities,d.hostname_ciphertext,d.group_id,e.channel,e.tool,e.mechanism,e.fingerprint,e.status,e.reported_at FROM page d LEFT JOIN dlp_enforcement e ON e.device_id=d.id ORDER BY d.id,e.channel,e.tool,e.mechanism`, cursor, device, group)
	if err != nil {
		return err
	}
	type candidate struct {
		id, kind                                      string
		hostname                                      string
		group                                         *string
		caps                                          []string
		channel, tool, mechanism, fingerprint, status *string
		reported                                      *time.Time
	}
	candidates := []candidate{}
	ids := []string{}
	for rows.Next() {
		var v candidate
		if err = rows.Scan(&v.id, &v.kind, &v.caps, &v.hostname, &v.group, &v.channel, &v.tool, &v.mechanism, &v.fingerprint, &v.status, &v.reported); err != nil {
			rows.Close()
			return err
		}
		if len(ids) == 0 || ids[len(ids)-1] != v.id {
			ids = append(ids, v.id)
		}
		candidates = append(candidates, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	next := ""
	if len(ids) > 100 {
		next = ids[99]
		ids = ids[:100]
	}
	settingsByDevice := map[string]DLPSettings{}
	confirmationRequired := map[string]bool{}
	contextRequired := map[string]bool{}
	items := []dlpDeviceStatus{}
	counts := map[string]int{}
	distinct := map[string]map[string]bool{}
	count := func(status, id string) {
		counts[status]++
		if distinct[status] == nil {
			distinct[status] = map[string]bool{}
		}
		distinct[status][id] = true
	}
	for _, v := range candidates {
		if next != "" && v.id > next {
			continue
		}
		settings, ok := settingsByDevice[v.id]
		if !ok {
			settings, err = a.readDLP(r.Context(), tx, s.OrganizationID, "endpoint", "device", v.id, 0)
			if err != nil {
				return err
			}
			confirmationRequired[v.id] = dlpHasConfirmation(dlpPolicyForDevice(settings.Policy, v.id, v.group), true)
			contextRequired[v.id] = len(dlpContextRequiredPolicy(dlpPolicyForDevice(settings.Policy, v.id, v.group)).Rules) > 0
			settings = dlpDeliverySettings(settings, v.caps)
			settingsByDevice[v.id] = settings
		}
		item := dlpDeviceStatus{DeviceID: v.id, Channel: "browser", Expected: settings.Fingerprint, Status: "pending", ReportedAt: v.reported}
		if !aggregate && hasPermission(s.Permissions, permDevicesRead) {
			item.Hostname, err = a.machineName(r, s.OrganizationID, v.id, v.hostname)
			if err != nil {
				return err
			}
			if item.Hostname == "" {
				item.Hostname = deviceAlias(v.id)
			}
		}
		if v.channel != nil {
			item.Channel = *v.channel
		}
		if v.tool != nil {
			item.Tool = *v.tool
		}
		if v.mechanism != nil {
			item.Mechanism = *v.mechanism
		}
		if v.fingerprint != nil {
			item.Applied = *v.fingerprint
		}
		if !settings.Policy.Inspection || item.Channel == "native" && !settings.Policy.NativeInspection {
			item.Status = "disabled"
		} else if !slices.Contains(v.caps, "dlp-v1") || confirmationRequired[v.id] && !slices.Contains(v.caps, "dlp-confirm-v1") || contextRequired[v.id] && !slices.Contains(v.caps, "dlp-contextual-v1") {
			item.Status = "needs_update"
		} else if item.Channel == "native" && !validNativeCapability(v.caps) {
			item.Status = "unavailable"
		} else if v.reported != nil && item.Expected == item.Applied {
			if now.Sub(*v.reported) > 3*time.Minute || v.reported.After(now.Add(30*time.Second)) {
				item.Status = "unavailable"
			} else if v.status != nil {
				item.Status = *v.status
			}
		}
		items = append(items, item)
		count(item.Status, v.id)
		if v.channel == nil && v.kind == "native" && Edition == "commercial" {
			native := item
			native.Channel = "native"
			if settings.Policy.NativeInspection && !validNativeCapability(v.caps) {
				native.Status = "unavailable"
			}
			if !settings.Policy.NativeInspection {
				native.Status = "disabled"
			}
			items = append(items, native)
			count(native.Status, v.id)
		}
	}
	if aggregate {
		floor := max(1, privacyFor(r).view.Config.K)
		counts = map[string]int{}
		for status, devices := range distinct {
			if len(devices) >= floor {
				counts[status] = len(devices)
			}
		}
		items = []dlpDeviceStatus{}
		if next != "" {
			next, err = a.sealIdentity(s.OrganizationID, "dlp-status-cursor", next)
			if err != nil {
				return err
			}
		}
	}
	reply(w, 200, map[string]any{"domain": domain, "items": items, "counts": counts, "counts_scope": "page", "next_cursor": next})
	return nil
}
