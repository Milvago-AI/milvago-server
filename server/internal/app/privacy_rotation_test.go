package app

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestAliasKeyRotation proves that rotating the organization's alias key breaks
// the continuity of every alias on purpose, keeps the subject row usable for the
// same person, revokes running reveals, and is refused to anyone but a fresh,
// interactive holder of identity.erase.
func TestAliasKeyRotation(t *testing.T) {
	p := newProjectionFixture(t)
	ctx := context.Background()
	body := map[string]string{"reason": "Synthetic rotation exercise"}
	var before string
	if e := p.admin.QueryRow(ctx, "SELECT alias FROM collaborators WHERE id=$1", p.subject).Scan(&before); e != nil {
		t.Fatal(e)
	}
	// Keep both searches on the fixture's period, independent of the host and
	// PostgreSQL clocks. Rotation must change the alias, not the time window.
	var occurred time.Time
	if err := p.admin.QueryRow(ctx, "SELECT occurred_at FROM shadow_events WHERE id=$1", p.event).Scan(&occurred); err != nil {
		t.Fatal(err)
	}
	count := func(t *testing.T, alias string) int {
		t.Helper()
		query := url.Values{
			"query": {alias},
			"from":  {occurred.Add(-time.Minute).Format(time.RFC3339Nano)},
			"to":    {occurred.Add(time.Minute).Format(time.RFC3339Nano)},
		}
		w := p.as("owner", "GET", "/api/shadow/events?"+query.Encode(), nil)
		requireHTTP(t, w, 200)
		var out struct {
			Items []json.RawMessage `json:"items"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		return len(out.Items)
	}
	t.Run("refused without the right credential", func(t *testing.T) {
		w := p.as("key", "POST", "/api/privacy/alias-key/rotate", body)
		requireHTTP(t, w, 403)
		if !strings.Contains(w.Body.String(), "session_required") {
			t.Fatal("an API key must be refused as a key, not as a permission", w.Body.String())
		}
		for _, actor := range []string{"admin", "viewer", "reporter"} {
			requireHTTP(t, p.as(actor, "POST", "/api/privacy/alias-key/rotate", body), 403)
		}
		requireHTTP(t, p.as("owner", "POST", "/api/privacy/alias-key/rotate", map[string]string{"reason": "short"}), 400)
		var unchanged string
		if e := p.admin.QueryRow(ctx, "SELECT alias FROM collaborators WHERE id=$1", p.subject).Scan(&unchanged); e != nil || unchanged != before {
			t.Fatal("a refused rotation changed an alias", e)
		}
	})
	t.Run("rotation re-aliases, revokes reveals and audits", func(t *testing.T) {
		requireHTTP(t, p.as("owner", "POST", "/api/subjects/"+p.subject+"/reveal", map[string]string{"reason": "Synthetic reveal before rotation"}), 200)
		detail := "/api/shadow/events/" + p.event + "?device_id=" + p.device
		if !strings.Contains(p.as("owner", "GET", detail, nil).Body.String(), p.s.name) {
			t.Fatal("reveal fixture missing")
		}
		if count(t, before) == 0 {
			t.Fatal("alias search fixture must match before rotation")
		}
		revision := readPrivacyTest(t, p.observabilityFixture).Revision
		w := p.as("owner", "POST", "/api/privacy/alias-key/rotate", body)
		requireHTTP(t, w, 200)
		var out struct {
			Subjects int   `json:"subjects"`
			Revision int64 `json:"revision"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil || out.Subjects < 1 || out.Revision != revision+1 {
			t.Fatal("unexpected rotation answer", w.Body.String(), e)
		}
		var after, digest string
		if e := p.admin.QueryRow(ctx, "SELECT alias,subject FROM collaborators WHERE id=$1", p.subject).Scan(&after, &digest); e != nil {
			t.Fatal(e)
		}
		if after == before || !strings.HasPrefix(after, "Subject ") {
			t.Fatal("alias did not rotate", before, after)
		}
		oldCount, newCount := count(t, before), count(t, after)
		if oldCount != 0 || newCount == 0 {
			t.Fatalf("search must follow the new alias: old=%d new=%d", oldCount, newCount)
		}
		if strings.Contains(p.as("owner", "GET", detail, nil).Body.String(), p.s.name) {
			t.Fatal("rotation left a reveal active")
		}
		var reveals, audits int
		if e := p.admin.QueryRow(ctx, "SELECT count(*) FROM identity_reveals").Scan(&reveals); e != nil || reveals != 0 {
			t.Fatal("reveals survived the rotation", e, reveals)
		}
		if e := p.admin.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action='privacy.alias_key.rotated' AND (details->>'subjects')::int=$1", out.Subjects).Scan(&audits); e != nil || audits != 1 {
			t.Fatal("rotation audit missing", e, audits)
		}
		// The same person, associated again, lands on the same row: the digest was
		// recomputed with the new key, so the upsert still finds it.
		tx, e := tenantTx(ctx, p.a.db, p.org)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		again, e := p.a.associateIdentity(ctx, tx, p.org, p.s.subject, p.s.email, p.s.name)
		if e != nil {
			t.Fatal(e)
		}
		if again != p.subject {
			t.Fatal("re-association created a second subject after rotation", again, p.subject)
		}
		var stored string
		if e = tx.QueryRow(ctx, "SELECT subject FROM collaborators WHERE id=$1", p.subject).Scan(&stored); e != nil || stored != digest {
			t.Fatal("re-association changed the rotated digest", e)
		}
	})
	t.Run("stale authentication is refused", func(t *testing.T) {
		if tag, e := p.admin.Exec(ctx, "UPDATE sessions SET mfa_verified_at=now()-interval '6 minutes' WHERE token_hash=$1", hash(p.owner.Value)); e != nil || tag.RowsAffected() != 1 {
			t.Fatal(e)
		}
		w := p.as("owner", "POST", "/api/privacy/alias-key/rotate", body)
		requireHTTP(t, w, 403)
		if !strings.Contains(w.Body.String(), "fresh_mfa_required") {
			t.Fatal("wrong refusal", w.Body.String())
		}
	})
}
