package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// callAs performs one request with an explicit identity: a console session (cookie
// plus its CSRF token), a bearer credential (API key or device), or neither.
func (f *observabilityFixture) callAs(method, path string, body any, cookie *http.Cookie, csrf, bearer string) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.a.config.AppURL)
	if cookie != nil {
		r.AddCookie(cookie)
		r.Header.Set("X-CSRF-Token", csrf)
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	f.a.Handler().ServeHTTP(w, r)
	return w
}

// sessionAs opens a synthetic console session for a new member holding role in
// the fixture organization. The admin connection must point at that organization.
func (f *observabilityFixture) sessionAs(t *testing.T, role string) (*http.Cookie, string) {
	t.Helper()
	ctx := context.Background()
	tag := strings.ToLower(randomToken()[:8])
	var user string
	if e := f.admin.QueryRow(ctx, "INSERT INTO users(subject,email,display_name) VALUES($1,$2,$3) RETURNING id", "groups-"+role+"-"+tag, role+"-"+tag+"@example.test", "Groups "+role).Scan(&user); e != nil {
		t.Fatal(e)
	}
	if _, e := f.admin.Exec(ctx, "INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3)", f.org, user, role); e != nil {
		t.Fatal(e)
	}
	token, csrf := randomToken(), randomToken()
	if _, e := f.admin.Exec(ctx, `INSERT INTO sessions(token_hash,user_id,organization_id,csrf_token,encrypted_tokens,mfa,expires_at,identity_expires_at) VALUES($1,$2,$3,$4,$5,true,$6,$6)`, hash(token), user, f.org, csrf, []byte("synthetic-session"), time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	return &http.Cookie{Name: cookieName("session"), Value: token}, csrf
}

// TestDeviceGroupsIntegration covers the device-group layer of the policy chain:
// device > group > organization. The revision a device receives must never
// decrease across group moves, because the agent refuses a lower one.
type groupRow struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	DeviceCount int    `json:"device_count"`
}

const missingGroupID = "00000000-0000-4000-8000-000000000000"

type deviceGroupsFixture struct {
	f            *observabilityFixture
	owner        func(string, string, any) *httptest.ResponseRecorder
	decodeJSON   func(*testing.T, *httptest.ResponseRecorder, any)
	viewer       *http.Cookie
	viewerCSRF   string
	deviceID     string
	deviceShadow func(*testing.T) ShadowSettings
	signedPolicy func(*testing.T) (int64, map[string]json.RawMessage)
	createGroup  func(*testing.T, string) string
	assign       func(*string) *httptest.ResponseRecorder
	listGroups   func(*testing.T) []groupRow
	groupA       string
	lastRevision int64
}

func newDeviceGroupsFixture(t *testing.T) *deviceGroupsFixture {
	f := newObservabilityFixture(t)
	owner := func(method, path string, body any) *httptest.ResponseRecorder {
		return f.callAs(method, path, body, f.owner, f.csrf, "")
	}
	decodeJSON := func(t *testing.T, w *httptest.ResponseRecorder, v any) {
		t.Helper()
		if e := json.Unmarshal(w.Body.Bytes(), v); e != nil {
			t.Fatal(e, w.Body.String())
		}
	}
	viewer, viewerCSRF := f.sessionAs(t, "viewer")

	enrollment := owner("POST", "/api/enrollments", map[string]string{"label": "Groups integration"})
	requireHTTP(t, enrollment, 201)
	var provision map[string]string
	decodeJSON(t, enrollment, &provision)
	enrolled := f.callAs("POST", "/v2/enroll", map[string]any{"token": provision["token"], "hostname": "groups-test-device", "platform": "test", "version": "0.2.0", "kind": "browser", "capabilities": []string{"browser.navigation", "browser.prompt"}}, nil, "", "")
	requireHTTP(t, enrolled, 201)
	var device map[string]string
	decodeJSON(t, enrolled, &device)
	credential, deviceID := device["credential"], device["device_id"]
	requireHTTP(t, owner("POST", "/api/devices/"+deviceID+"/approve", map[string]any{}), 200)

	deviceShadow := func(t *testing.T) ShadowSettings {
		t.Helper()
		w := owner("GET", "/api/devices/"+deviceID+"/shadow", nil)
		requireHTTP(t, w, 200)
		var s ShadowSettings
		decodeJSON(t, w, &s)
		return s
	}
	// signedPolicy reads what the agent itself receives.
	signedPolicy := func(t *testing.T) (int64, map[string]json.RawMessage) {
		t.Helper()
		w := f.callAs("GET", "/v3/policy", nil, nil, "", credential)
		requireHTTP(t, w, 200)
		var envelope map[string]string
		decodeJSON(t, w, &envelope)
		raw, e := base64.StdEncoding.DecodeString(envelope["payload"])
		if e != nil {
			t.Fatal(e)
		}
		var payload struct {
			Revision int64                      `json:"revision"`
			Config   map[string]json.RawMessage `json:"config"`
		}
		if e = json.Unmarshal(raw, &payload); e != nil {
			t.Fatal(e)
		}
		return payload.Revision, payload.Config
	}
	createGroup := func(t *testing.T, name string) string {
		t.Helper()
		w := owner("POST", "/api/groups", map[string]string{"name": name, "description": "Integration " + name})
		requireHTTP(t, w, 201)
		var g struct {
			ID string `json:"id"`
		}
		decodeJSON(t, w, &g)
		if !uuidPattern.MatchString(g.ID) {
			t.Fatal("group id missing", w.Body.String())
		}
		return g.ID
	}
	assign := func(group *string) *httptest.ResponseRecorder {
		return owner("PUT", "/api/devices/"+deviceID+"/group", map[string]any{"group_id": group})
	}
	listGroups := func(t *testing.T) []groupRow {
		t.Helper()
		w := owner("GET", "/api/groups", nil)
		requireHTTP(t, w, 200)
		var out struct {
			Items []groupRow `json:"items"`
		}
		decodeJSON(t, w, &out)
		return out.Items
	}
	return &deviceGroupsFixture{f: f, owner: owner, decodeJSON: decodeJSON, viewer: viewer, viewerCSRF: viewerCSRF, deviceID: deviceID, deviceShadow: deviceShadow, signedPolicy: signedPolicy, createGroup: createGroup, assign: assign, listGroups: listGroups}
}

func TestDeviceGroupsIntegration(t *testing.T) {
	x := newDeviceGroupsFixture(t)
	t.Run("crud and validation", x.assertCRUD)
	if x.groupA == "" {
		t.Fatal("group fixture missing")
	}
	t.Run("assignment, effective chain and monotonic revision", x.assertAssignment)
	t.Run("permissions", x.assertPermissions)
	t.Run("another organization's group is invisible", x.assertForeignGroup)
	t.Run("edition capabilities apply to group overrides", x.assertCapabilities)
}

func (x *deviceGroupsFixture) assertCRUD(t *testing.T) {
	owner := x.owner
	deviceID := x.deviceID
	createGroup := x.createGroup
	assign := x.assign
	listGroups := x.listGroups
	groupA := x.groupA
	requireHTTP(t, owner("POST", "/api/groups", map[string]string{"name": ""}), 400)
	requireHTTP(t, owner("POST", "/api/groups", map[string]string{"name": strings.Repeat("a", 81)}), 400)
	requireHTTP(t, owner("POST", "/api/groups", map[string]string{"name": "bad\x01name"}), 400)
	requireHTTP(t, owner("POST", "/api/groups", map[string]any{"name": "x", "unexpected": true}), 400)
	groupA = createGroup(t, "Group A")
	requireHTTP(t, owner("POST", "/api/groups", map[string]string{"name": "group a"}), 409)
	items := listGroups(t)
	if len(items) != 1 || items[0].ID != groupA || items[0].DeviceCount != 0 {
		t.Fatalf("unexpected listing: %+v", items)
	}
	hostile := "<img src=x onerror=alert(1)>"
	requireHTTP(t, owner("PUT", "/api/groups/"+groupA, map[string]string{"name": "Group A renamed", "description": hostile}), 200)
	items = listGroups(t)
	if items[0].Name != "Group A renamed" || items[0].Description != hostile {
		t.Fatalf("rename not stored literally: %+v", items[0])
	}
	requireHTTP(t, owner("PUT", "/api/groups/not-a-uuid", map[string]string{"name": "x"}), 400)
	requireHTTP(t, owner("PUT", "/api/groups/"+missingGroupID, map[string]string{"name": "x"}), 404)
	requireHTTP(t, owner("DELETE", "/api/groups/"+missingGroupID, nil), 404)
	requireHTTP(t, owner("GET", "/api/groups/"+missingGroupID+"/shadow", nil), 404)
	requireHTTP(t, assign(&[]string{missingGroupID}[0]), 404)
	requireHTTP(t, owner("PUT", "/api/devices/"+deviceID+"/group", map[string]any{"group_id": "not-a-uuid"}), 400)

	x.groupA = groupA
}

func (x *deviceGroupsFixture) assertAssignment(t *testing.T) {
	s := x.assertGroupOverride(t)
	x.assertDeviceMovesAndDeletion(t, s)
}

func (x *deviceGroupsFixture) step(t *testing.T, label string) ShadowSettings {
	t.Helper()
	s := x.deviceShadow(t)
	signed, _ := x.signedPolicy(t)
	if signed != s.Revision {
		t.Fatalf("%s: the agent receives revision %d, the console shows %d", label, signed, s.Revision)
	}
	if s.Revision <= x.lastRevision {
		t.Fatalf("%s: revision %d did not grow past %d", label, s.Revision, x.lastRevision)
	}
	x.lastRevision = s.Revision
	return s
}

func (x *deviceGroupsFixture) assertGroupOverride(t *testing.T) ShadowSettings {
	owner, decodeJSON := x.owner, x.decodeJSON
	deviceShadow, signedPolicy := x.deviceShadow, x.signedPolicy
	assign, listGroups := x.assign, x.listGroups
	groupA, step := x.groupA, x.step
	base := step(t, "baseline")
	if base.Config.Protection.BlockUploads {
		t.Fatal("fixture: uploads already blocked at organization level")
	}
	requireHTTP(t, assign(&groupA), 200)
	step(t, "assigned to A")
	w := owner("GET", "/api/devices", nil)
	requireHTTP(t, w, 200)
	if !strings.Contains(w.Body.String(), `"group_id":"`+groupA+`"`) || !strings.Contains(w.Body.String(), `"group_name":"Group A renamed"`) {
		t.Fatal("device listing does not carry the group", w.Body.String())
	}
	if items := listGroups(t); items[0].DeviceCount != 1 {
		t.Fatalf("device_count %d, want 1", items[0].DeviceCount)
	}
	requireHTTP(t, assign(&groupA), 200)
	if s := deviceShadow(t); s.Revision != x.lastRevision {
		t.Fatal("re-assigning the same group changed the revision")
	}
	g := owner("GET", "/api/groups/"+groupA+"/shadow", nil)
	requireHTTP(t, g, 200)
	var gs ShadowSettings
	decodeJSON(t, g, &gs)
	if len(gs.InheritSections) != len(overrideSections) {
		t.Fatalf("a group without override should inherit every section, got %v", gs.InheritSections)
	}
	p := gs.Config.Protection
	p.BlockUploads = true
	requireHTTP(t, owner("PUT", "/api/groups/"+groupA+"/shadow", map[string]any{"revision": gs.Revision, "config": map[string]any{"protection": p}, "inherit_sections": []string{}}), 200)
	requireHTTP(t, owner("PUT", "/api/groups/"+groupA+"/shadow", map[string]any{"revision": gs.Revision, "config": map[string]any{"protection": p}, "inherit_sections": []string{}}), 409)
	requireHTTP(t, owner("PUT", "/api/groups/"+groupA+"/shadow", map[string]any{"revision": gs.Revision, "config": map[string]any{"enrollment": map[string]any{}}, "inherit_sections": []string{}}), 400)
	s := step(t, "group policy saved")
	if !s.Config.Protection.BlockUploads {
		t.Fatal("group override not effective on the device")
	}
	if from := s.InheritedFrom["protection"]; from.GroupID != groupA || from.Name != "Group A renamed" {
		t.Fatalf("protection provenance %+v, want group %s", from, groupA)
	}
	if !slices.Contains(s.InheritSections, "protection") {
		t.Fatal("the device should still inherit protection")
	}
	if _, cfg := signedPolicy(t); !strings.Contains(string(cfg["protection"]), `"block_uploads":true`) {
		t.Fatal("the signed policy does not carry the group's setting", string(cfg["protection"]))
	}
	return s
}

func (x *deviceGroupsFixture) assertDeviceMovesAndDeletion(t *testing.T, s ShadowSettings) {
	f, owner := x.f, x.owner
	deviceID, createGroup := x.deviceID, x.createGroup
	assign, groupA, step := x.assign, x.groupA, x.step
	ctx := context.Background()
	dp := s.Config.Protection
	dp.BlockUploads = false
	requireHTTP(t, owner("PUT", "/api/devices/"+deviceID+"/shadow", map[string]any{"revision": s.Revision, "config": map[string]any{"protection": dp}, "inherit_sections": []string{}}), 200)
	s = step(t, "device derogation")
	if s.Config.Protection.BlockUploads {
		t.Fatal("the device derogation did not win over the group")
	}
	requireHTTP(t, owner("PUT", "/api/devices/"+deviceID+"/shadow", map[string]any{"revision": s.Revision, "config": map[string]any{}, "inherit_sections": []string{"protection"}}), 200)
	s = step(t, "device inherits again")
	if !s.Config.Protection.BlockUploads {
		t.Fatal("the device did not return to the group value")
	}
	groupB := createGroup(t, "Group B")
	requireHTTP(t, assign(&groupB), 200)
	s = step(t, "moved to B")
	if s.Config.Protection.BlockUploads {
		t.Fatal("group A override still applied after moving to B")
	}
	requireHTTP(t, assign(&groupA), 200)
	s = step(t, "moved back to A")
	if !s.Config.Protection.BlockUploads {
		t.Fatal("group A override missing after moving back")
	}
	requireHTTP(t, assign(nil), 200)
	s = step(t, "detached")
	if s.Config.Protection.BlockUploads {
		t.Fatal("detached device still carries the group override")
	}
	requireHTTP(t, assign(&groupA), 200)
	step(t, "re-attached to A")
	requireHTTP(t, owner("DELETE", "/api/groups/"+groupA, nil), 200)
	s = step(t, "group deleted while a member")
	if s.Config.Protection.BlockUploads {
		t.Fatal("deleted group's override still applied")
	}
	w := owner("GET", "/api/devices", nil)
	requireHTTP(t, w, 200)
	if strings.Contains(w.Body.String(), groupA) || !strings.Contains(w.Body.String(), `"group_id":null`) {
		t.Fatal("deleted group still referenced by the device", w.Body.String())
	}
	var n int
	if e := f.admin.QueryRow(ctx, "SELECT count(*) FROM shadow_group_overrides WHERE group_id=$1", groupA).Scan(&n); e != nil || n != 0 {
		t.Fatal("group override survived the group", e, n)
	}
	for _, action := range []string{"device_group.create", "device_group.update", "device_group.delete", "device.group", "shadow.group.update", "shadow.device.update"} {
		if e := f.admin.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action=$1", action).Scan(&n); e != nil || n == 0 {
			t.Fatalf("no audit entry for %s (%v)", action, e)
		}
	}
	groupA = groupB
	x.groupA = groupA
}

func (x *deviceGroupsFixture) assertPermissions(t *testing.T) {
	f := x.f
	owner := x.owner
	decodeJSON := x.decodeJSON
	viewer := x.viewer
	viewerCSRF := x.viewerCSRF
	deviceID := x.deviceID
	groupA := x.groupA
	requireHTTP(t, f.callAs("GET", "/api/groups", nil, viewer, viewerCSRF, ""), 200)
	requireHTTP(t, f.callAs("POST", "/api/groups", map[string]string{"name": "Viewer group"}, viewer, viewerCSRF, ""), 403)
	requireHTTP(t, f.callAs("PUT", "/api/devices/"+deviceID+"/group", map[string]any{"group_id": groupA}, viewer, viewerCSRF, ""), 403)
	requireHTTP(t, f.callAs("DELETE", "/api/groups/"+groupA, nil, viewer, viewerCSRF, ""), 403)
	requireHTTP(t, f.callAs("GET", "/api/groups/"+groupA+"/shadow", nil, viewer, viewerCSRF, ""), 403)
	mint := func(t *testing.T, perms []string) string {
		t.Helper()
		w := owner("POST", "/api/profile/api-keys", map[string]any{"name": "groups " + strings.Join(perms, "+"), "expires_in_days": 30, "permissions": perms})
		requireHTTP(t, w, 201)
		var k struct {
			Secret string `json:"secret"`
		}
		decodeJSON(t, w, &k)
		return k.Secret
	}
	readKey := mint(t, []string{"devices.read"})
	requireHTTP(t, f.callAs("GET", "/api/groups", nil, nil, "", readKey), 200)
	requireHTTP(t, f.callAs("POST", "/api/groups", map[string]string{"name": "Key group"}, nil, "", readKey), 403)
	fleetKey := mint(t, []string{"devices.read", "devices.manage"})
	requireHTTP(t, f.callAs("PUT", "/api/groups/"+groupA, map[string]string{"name": "Renamed by key"}, nil, "", fleetKey), 200)
	requireHTTP(t, f.callAs("GET", "/api/groups/"+groupA+"/shadow", nil, nil, "", fleetKey), 403)
	requireHTTP(t, f.callAs("PUT", "/api/groups/"+groupA+"/shadow", map[string]any{"revision": 0, "config": map[string]any{}, "inherit_sections": []string{}}, nil, "", fleetKey), 403)
	requireHTTP(t, f.callAs("POST", "/api/groups", map[string]string{"name": "No CSRF"}, f.owner, "", ""), 403)

}

func (x *deviceGroupsFixture) assertForeignGroup(t *testing.T) {
	f := x.f
	owner := x.owner
	assign := x.assign
	ctx := context.Background()
	var other string
	if e := f.admin.QueryRow(ctx, "INSERT INTO organizations(name,parent_id) VALUES('Other organization',$1) RETURNING id", f.org).Scan(&other); e != nil {
		t.Fatal(e)
	}
	setTenant(t, f.admin, other)
	var foreign string
	if e := f.admin.QueryRow(ctx, "INSERT INTO device_groups(organization_id,name) VALUES($1,'Foreign group') RETURNING id", other).Scan(&foreign); e != nil {
		t.Fatal(e)
	}
	requireHTTP(t, assign(&foreign), 404)
	requireHTTP(t, owner("GET", "/api/groups/"+foreign+"/shadow", nil), 404)
	requireHTTP(t, owner("PUT", "/api/groups/"+foreign, map[string]string{"name": "Taken over"}), 404)
	requireHTTP(t, owner("DELETE", "/api/groups/"+foreign, nil), 404)
	w := owner("GET", "/api/groups", nil)
	requireHTTP(t, w, 200)
	if strings.Contains(w.Body.String(), foreign) {
		t.Fatal("foreign group listed")
	}
	tx, e := tenantTx(ctx, f.a.db, other)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	var n int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM device_groups").Scan(&n); e != nil || n != 1 {
		t.Fatal("the other tenant sees the wrong rows", e, n)
	}
	if _, e = tx.Exec(ctx, "INSERT INTO device_groups(organization_id,name) VALUES($1,'Cross tenant')", f.org); e == nil {
		t.Fatal("cross-tenant insert accepted")
	}

}

func (x *deviceGroupsFixture) assertCapabilities(t *testing.T) {
	owner := x.owner
	decodeJSON := x.decodeJSON
	groupA := x.groupA
	g := owner("GET", "/api/groups/"+groupA+"/shadow", nil)
	requireHTTP(t, g, 200)
	var gs ShadowSettings
	decodeJSON(t, g, &gs)
	w := owner("PUT", "/api/groups/"+groupA+"/shadow", map[string]any{"revision": gs.Revision, "config": map[string]any{"classification": map[string]any{"browser": []string{"email"}, "coding": []string{}, "medical_terms": []string{}}}, "inherit_sections": []string{}})
	if Edition == "community" {
		requireHTTP(t, w, 409)
	} else {
		requireHTTP(t, w, 200)
	}

}
