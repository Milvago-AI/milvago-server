package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMachineNamesIndependentOfPersonalIdentity(t *testing.T) {
	p := newProjectionFixture(t)
	testMachineSessionOwnership(t, p)
	detail := "/api/shadow/events/" + p.event + "?device_id=" + p.device
	var occurred time.Time
	if e := p.admin.QueryRow(context.Background(), "SELECT occurred_at FROM shadow_events WHERE id=$1", p.event).Scan(&occurred); e != nil {
		t.Fatal(e)
	}
	period := "?from=" + occurred.UTC().Add(-time.Minute).Format(time.RFC3339) + "&to=" + occurred.UTC().Add(time.Minute).Format(time.RFC3339)
	paths := []string{"/api/devices", "/api/events", "/api/shadow/events" + period, detail}
	testMachineNamesInRoutes(t, p, paths)
	t.Run("active grant carries bounded expiry", func(t *testing.T) { testMachineActiveGrantExpiry(t, p, detail) })
	t.Run("aggregate management names without individual usage", func(t *testing.T) { testMachineAggregateManagement(t, p, paths) })
	t.Run("missing name is separate from technical identifier", func(t *testing.T) { testMachineMissingName(t, p) })
}

func testMachineActiveGrantExpiry(t *testing.T, p *projectionFixture, detail string) {
	w := p.as("owner", "POST", "/api/subjects/"+p.subject+"/reveal", map[string]string{"reason": "Synthetic expiry verification"})
	requireHTTP(t, w, 200)
	var grant struct {
		Expires time.Time `json:"expires_at"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &grant); e != nil || grant.Expires.IsZero() {
		t.Fatal("grant expiry absent", e)
	}
	w = p.as("owner", "GET", detail, nil)
	requireHTTP(t, w, 200)
	var out struct {
		Event ShadowEventView `json:"event"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	if out.Event.IdentityExpiresAt == nil || !out.Event.IdentityExpiresAt.Equal(grant.Expires) {
		t.Fatal("projection expiry differs from grant")
	}
	tag, e := p.admin.Exec(context.Background(), "UPDATE identity_reveals SET expires_at=clock_timestamp()-interval '1 second' WHERE collaborator_id=$1", p.subject)
	if e != nil || tag.RowsAffected() != 1 {
		t.Fatal("expiry precondition missing", e)
	}
	w = p.as("owner", "GET", detail, nil)
	requireHTTP(t, w, 200)
	p.scan(t, "expired grant", w.Body.Bytes(), p.s.host)
	if strings.Contains(w.Body.String(), "identity_expires_at") {
		t.Fatal("expired grant still projected")
	}
}

func testMachineAggregateManagement(t *testing.T, p *projectionFixture, paths []string) {
	cfg := defaultPrivacy()
	cfg.AggregateOnly = true
	requireHTTP(t, putPrivacyTest(t, p.observabilityFixture, cfg), 200)
	session := p.as("owner", "GET", "/api/session", nil)
	requireHTTP(t, session, 200)
	var view struct {
		Privacy struct {
			AggregateOnly bool `json:"aggregate_only"`
		} `json:"privacy"`
	}
	if e := json.Unmarshal(session.Body.Bytes(), &view); e != nil || !view.Privacy.AggregateOnly {
		t.Fatal("session privacy state missing", e)
	}
	w := p.as("owner", "GET", "/api/devices", nil)
	requireHTTP(t, w, 200)
	if !strings.Contains(w.Body.String(), p.s.host) {
		t.Fatal("administrative machine name absent")
	}
	p.scan(t, "aggregate devices", w.Body.Bytes(), p.s.host)
	for _, path := range paths[1:] {
		w = p.as("owner", "GET", path, nil)
		requireHTTP(t, w, 403)
	}
}

func testMachineMissingName(t *testing.T, p *projectionFixture) {
	tag, e := p.admin.Exec(context.Background(), "UPDATE devices SET hostname_ciphertext='' WHERE id=$1", p.device)
	if e != nil || tag.RowsAffected() != 1 {
		t.Fatal("missing-name precondition", e)
	}
	w := p.as("owner", "GET", "/api/devices", nil)
	requireHTTP(t, w, 200)
	var out struct {
		Items []struct{ ID, Hostname string } `json:"items"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	found := false
	for _, v := range out.Items {
		if v.ID == p.device {
			found = true
			if v.Hostname != "" {
				t.Fatal("missing name substituted with identity")
			}
		}
	}
	if !found {
		t.Fatal("device absent")
	}
}

func testMachineSessionOwnership(t *testing.T, p *projectionFixture) {
	for _, actor := range []string{"owner", "admin", "viewer", "reporter", "key"} {
		w := p.as(actor, "GET", "/api/session", nil)
		requireHTTP(t, w, 200)
		var v struct {
			InstanceOwner bool `json:"is_instance_owner"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil {
			t.Fatal(e)
		}
		if v.InstanceOwner != (actor == "owner") {
			t.Fatal("incorrect instance ownership indicator", actor)
		}
	}
}

func testMachineNamesInRoutes(t *testing.T, p *projectionFixture, paths []string) {
	for _, path := range paths {
		for _, actor := range []string{"owner", "admin", "viewer", "key"} {
			w := p.as(actor, "GET", path, nil)
			requireHTTP(t, w, 200)
			if !strings.Contains(w.Body.String(), p.s.host) {
				t.Fatalf("%s %s: machine name absent", actor, path)
			}
			p.scan(t, actor+" "+path, w.Body.Bytes(), p.s.host)
			sep := "?"
			if strings.Contains(path, "?") {
				sep = "&"
			}
			w = p.as(actor, "GET", path+sep+"identity=aliases", nil)
			requireHTTP(t, w, 200)
			p.scan(t, actor+" aliases "+path, w.Body.Bytes())
			if !strings.Contains(w.Body.String(), deviceAlias(p.device)) {
				t.Fatal("explicit alias absent", path)
			}
		}
	}
}
