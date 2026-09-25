package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDetectionCatalogImport(t *testing.T) {
	p := newProjectionFixture(t)
	// Manual import travels the console route, closed without MILVAGO_DEBUG; the
	// automatic publisher import has its own path and its own test.
	p.a.config.ConsoleDebug = true
	ctx := context.Background()
	var revision int64
	if err := p.admin.QueryRow(ctx, "SELECT max(revision) FROM detection_catalogs").Scan(&revision); err != nil {
		t.Fatal(err)
	}
	raw, key := publisherSigned(t, detectionFactory, 10, time.Now().UTC())
	p.a.config.PublisherPublicKey = key
	var envelope publisherEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"expected_revision": revision, "envelope": envelope, "publish": false}
	for _, actor := range []string{"admin", "viewer", "reporter", "key"} {
		t.Run("refuse_"+actor, func(t *testing.T) { requireHTTP(t, p.as(actor, "POST", "/api/detection/catalog/import", body), 403) })
	}
	t.Run("preview_has_no_writes", func(t *testing.T) {
		w := p.as("owner", "POST", "/api/detection/catalog/import", body)
		requireHTTP(t, w, 200)
		var out struct {
			Published bool
			Content   DetectionContent
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Published || len(out.Content.Providers) == 0 {
			t.Fatal("preview missing", err)
		}
		var got, remote int64
		if err := p.admin.QueryRow(ctx, "SELECT max(revision),(SELECT publisher_revision FROM publisher_client_state) FROM detection_catalogs").Scan(&got, &remote); err != nil || got != revision || remote != 0 {
			t.Fatal("preview mutated state", got, remote, err)
		}
	})
	t.Run("invalid_and_conflicting_imports_are_refused", func(t *testing.T) {
		badEnvelope := envelope
		badEnvelope.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		requireHTTP(t, p.as("owner", "POST", "/api/detection/catalog/import", map[string]any{"expected_revision": revision, "envelope": badEnvelope, "publish": true}), 400)
		requireHTTP(t, p.as("owner", "POST", "/api/detection/catalog/import", map[string]any{"expected_revision": revision + 1, "envelope": envelope, "publish": true}), 409)
	})
	t.Run("publication_is_signed_for_the_organization_and_replay_is_refused", func(t *testing.T) {
		body["publish"] = true
		w := p.as("owner", "POST", "/api/detection/catalog/import", body)
		requireHTTP(t, w, 200)
		var out struct {
			Revision  int64
			Published bool
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || !out.Published || out.Revision <= revision {
			t.Fatal("publication missing", err)
		}
		revision = out.Revision
		body["expected_revision"] = revision
		requireHTTP(t, p.as("owner", "POST", "/api/detection/catalog/import", body), 409)
		var count int
		if err := p.admin.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action='detection.catalog.import'").Scan(&count); err != nil || count != 1 {
			t.Fatal("publication audit missing or replay wrote", err, count)
		}
		credential := randomToken()
		if tag, err := p.admin.Exec(ctx, "UPDATE devices SET credential_hash=$1 WHERE id=$2", hash(credential), p.device); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("device credential fixture missing", err)
		}
		r := httptest.NewRequest("GET", "/v3/detection-catalog", nil)
		r.Header.Set("Authorization", "Bearer "+credential)
		deviceResponse := httptest.NewRecorder()
		p.a.mux.ServeHTTP(deviceResponse, r)
		requireHTTP(t, deviceResponse, 200)
		var signed publisherEnvelope
		if err := json.Unmarshal(deviceResponse.Body.Bytes(), &signed); err != nil {
			t.Fatal(err)
		}
		payload, err := base64.StdEncoding.DecodeString(signed.Payload)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := base64.StdEncoding.DecodeString(signed.Signature)
		if err != nil || !ed25519.Verify(p.a.policyKey(p.org).Public().(ed25519.PublicKey), payload, sig) {
			t.Fatal("organization signature invalid", err)
		}
		var header publisherHeader
		if err = json.Unmarshal(payload, &header); err != nil || header.Revision != revision {
			t.Fatal("device revision mismatch", err)
		}
		content, err := base64.StdEncoding.DecodeString(header.Content)
		if err != nil || !bytes.Equal(content, detectionFactory) {
			t.Fatal("imported bytes changed", err)
		}
	})
	t.Run("fresh_mfa_required", func(t *testing.T) {
		if tag, err := p.admin.Exec(ctx, "UPDATE sessions SET mfa_verified_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1", hash(p.owner.Value)); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("stale MFA fixture missing", err)
		}
		body["publish"] = false
		requireHTTP(t, p.as("owner", "POST", "/api/detection/catalog/import", body), 403)
	})
}
