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

type detectionImportFixture struct {
	p *projectionFixture

	revision int64
	envelope publisherEnvelope
	body     map[string]any
}

func newDetectionImportFixture(t *testing.T) *detectionImportFixture {
	t.Helper()
	p := newProjectionFixture(t)
	// Manual import uses the console route; the automatic publisher has a separate path.
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
	return &detectionImportFixture{p: p, revision: revision, envelope: envelope,
		body: map[string]any{"expected_revision": revision, "envelope": envelope, "publish": false}}
}

func (fixture *detectionImportFixture) assertPreview(t *testing.T, ctx context.Context) {
	w := fixture.p.as("owner", "POST", "/api/detection/catalog/import", fixture.body)
	requireHTTP(t, w, 200)
	var out struct {
		Published bool
		Content   DetectionContent
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Published || len(out.Content.Providers) == 0 {
		t.Fatal("preview missing", err)
	}
	var got, remote int64
	if err := fixture.p.admin.QueryRow(ctx, "SELECT max(revision),(SELECT publisher_revision FROM publisher_client_state) FROM detection_catalogs").Scan(&got, &remote); err != nil || got != fixture.revision || remote != 0 {
		t.Fatal("preview mutated state", got, remote, err)
	}
}

func (fixture *detectionImportFixture) assertInvalidImports(t *testing.T, ctx context.Context) {
	badEnvelope := fixture.envelope
	badEnvelope.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	requireHTTP(t, fixture.p.as("owner", "POST", "/api/detection/catalog/import", map[string]any{"expected_revision": fixture.revision, "envelope": badEnvelope, "publish": true}), 400)
	requireHTTP(t, fixture.p.as("owner", "POST", "/api/detection/catalog/import", map[string]any{"expected_revision": fixture.revision + 1, "envelope": fixture.envelope, "publish": true}), 409)
}

func (fixture *detectionImportFixture) assertImportedForDevice(t *testing.T, ctx context.Context) {
	credential := randomToken()
	if tag, err := fixture.p.admin.Exec(ctx, "UPDATE devices SET credential_hash=$1 WHERE id=$2", hash(credential), fixture.p.device); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("device credential fixture missing", err)
	}
	request := httptest.NewRequest("GET", "/v3/detection-catalog", nil)
	request.Header.Set("Authorization", "Bearer "+credential)
	response := httptest.NewRecorder()
	fixture.p.a.mux.ServeHTTP(response, request)
	requireHTTP(t, response, 200)
	var signed publisherEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &signed); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(signed.Payload)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(fixture.p.a.policyKey(fixture.p.org).Public().(ed25519.PublicKey), payload, signature) {
		t.Fatal("organization signature invalid", err)
	}
	var header publisherHeader
	if err = json.Unmarshal(payload, &header); err != nil || header.Revision != fixture.revision {
		t.Fatal("device revision mismatch", err)
	}
	content, err := base64.StdEncoding.DecodeString(header.Content)
	if err != nil || !bytes.Equal(content, detectionFactory) {
		t.Fatal("imported bytes changed", err)
	}
}

func (fixture *detectionImportFixture) assertPublication(t *testing.T, ctx context.Context) {
	fixture.body["publish"] = true
	w := fixture.p.as("owner", "POST", "/api/detection/catalog/import", fixture.body)
	requireHTTP(t, w, 200)
	var out struct {
		Revision  int64
		Published bool
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || !out.Published || out.Revision <= fixture.revision {
		t.Fatal("publication missing", err)
	}
	fixture.revision = out.Revision
	fixture.body["expected_revision"] = fixture.revision
	requireHTTP(t, fixture.p.as("owner", "POST", "/api/detection/catalog/import", fixture.body), 409)
	var count int
	if err := fixture.p.admin.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action='detection.catalog.import'").Scan(&count); err != nil || count != 1 {
		t.Fatal("publication audit missing or replay wrote", err, count)
	}
	fixture.assertImportedForDevice(t, ctx)
}

func (fixture *detectionImportFixture) assertFreshMFA(t *testing.T, ctx context.Context) {
	if tag, err := fixture.p.admin.Exec(ctx, "UPDATE sessions SET mfa_verified_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1", hash(fixture.p.owner.Value)); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("stale MFA fixture missing", err)
	}
	fixture.body["publish"] = false
	requireHTTP(t, fixture.p.as("owner", "POST", "/api/detection/catalog/import", fixture.body), 403)
}

func TestDetectionCatalogImport(t *testing.T) {
	fixture := newDetectionImportFixture(t)
	ctx := context.Background()
	for _, actor := range []string{"admin", "viewer", "reporter", "key"} {
		t.Run("refuse_"+actor, func(t *testing.T) {
			requireHTTP(t, fixture.p.as(actor, "POST", "/api/detection/catalog/import", fixture.body), 403)
		})
	}
	t.Run("preview_has_no_writes", func(t *testing.T) { fixture.assertPreview(t, ctx) })
	t.Run("invalid_and_conflicting_imports_are_refused", func(t *testing.T) { fixture.assertInvalidImports(t, ctx) })
	t.Run("publication_is_signed_for_the_organization_and_replay_is_refused", func(t *testing.T) { fixture.assertPublication(t, ctx) })
	t.Run("fresh_mfa_required", func(t *testing.T) { fixture.assertFreshMFA(t, ctx) })
}
