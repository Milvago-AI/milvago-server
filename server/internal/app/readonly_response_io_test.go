package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A blocked ResponseWriter isolates resource lifetime from network buffering.
// The fixture deliberately does not establish a transport-level availability effect.
func serveReadOnlyWithBlockedWriter(t *testing.T, f *observabilityFixture, request *http.Request, device string, whileBlocked ...func()) *httptest.ResponseRecorder {
	t.Helper()
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	request = request.WithContext(ctx)
	writer := &discoveryDeniedBlockingWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), proceed: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(writer.proceed) }) }
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("read-only request worker did not stop")
		}
	})
	go func() {
		defer close(done)
		f.a.Handler().ServeHTTP(writer, request)
	}()
	select {
	case <-writer.entered:
	case <-done:
		t.Fatal("request ended before response I/O")
	case <-time.After(5 * time.Second):
		t.Fatal("read-only request did not reach response I/O")
	}
	if acquired := f.a.db.Stat().AcquiredConns(); acquired != 0 {
		t.Fatal("read-only response retained a pool connection", acquired)
	}
	if slots := len(f.a.eventSlots); slots != 0 {
		t.Fatal("read-only response retained an event slot", slots)
	}
	probeCtx, stopProbe := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopProbe()
	probe, err := f.admin.Begin(probeCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Rollback(probeCtx)
	if _, err = probe.Exec(probeCtx, `SET LOCAL lock_timeout='500ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err = probe.Exec(probeCtx, `SELECT pg_advisory_xact_lock(`+barrierKeySQL+`)`, f.org); err != nil {
		t.Fatal("read-only response retained the privacy barrier", err)
	}
	if _, err = probe.Exec(probeCtx, `SELECT pg_advisory_xact_lock(7069202)`); err != nil {
		t.Fatal("read-only response retained the policy barrier", err)
	}
	var lockedDevice string
	if err = probe.QueryRow(probeCtx, `SELECT id::text FROM devices WHERE organization_id=$1 AND id=$2 FOR UPDATE`, f.org, device).Scan(&lockedDevice); err != nil || lockedDevice != device {
		t.Fatal("read-only response retained the device row", err)
	}
	if err = probe.Commit(probeCtx); err != nil {
		t.Fatal("independent exclusive update did not commit while writer was blocked", err)
	}
	select {
	case <-done:
		t.Fatal("writer was not still blocked during the independent transaction")
	default:
	}
	for _, check := range whileBlocked {
		check()
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("read-only response did not finish after writer resumed")
	}
	return writer.ResponseRecorder
}

func writeReadOnlyResponseFixture(t *testing.T, directory, name string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateReadOnlyResponsesEndTransactionBeforeIO(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	credential := randomToken()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,kind,status)
 VALUES($1,$2,'synthetic-read-only-device','linux','0.2.0','browser','approved') RETURNING id`, f.org, hash(credential)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	config := defaultShadowConfig()
	config.Operations.Updates.Enabled = true
	config.Operations.Updates.Percentage = 100
	rawConfig, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `INSERT INTO shadow_settings(organization_id,configuration) VALUES($1,$2)
 ON CONFLICT(organization_id) DO UPDATE SET configuration=excluded.configuration,revision=nextval('shadow_revision')`, f.org, rawConfig); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	t.Setenv("MILVAGO_INSTALLER_DIRECTORY", directory)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, 32))
	f.a.config.UpdatePublicKey = key.Public().(ed25519.PublicKey)
	artifact := []byte("synthetic read-only signed artifact")
	digest := sha256.Sum256(artifact)
	sha := hex.EncodeToString(digest[:])
	if err = os.WriteFile(filepath.Join(directory, "synthetic.tar.gz"), artifact, 0600); err != nil {
		t.Fatal(err)
	}
	writeReadOnlyResponseFixture(t, directory, Edition+"-linux.json", InstallerBundle{Version: "0.2.1", Artifact: "synthetic.tar.gz", SHA256: sha, Size: int64(len(artifact))})
	manifest := UpdateManifest{Version: "0.2.1", Edition: "community", Platform: "linux", Protocol: 2, SHA256: sha, Size: int64(len(artifact)), ExpiresAt: time.Now().Add(time.Hour), Artifact: "/v2/update/artifact/" + sha, RollbackFrom: []string{}}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestEnvelope := signedEnvelope{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))}
	successor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{24}, 32)).Public().(ed25519.PublicKey)
	anchorPayload, err := json.Marshal(map[string]any{"next_public_key": base64.StdEncoding.EncodeToString(successor), "expires_at": time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	anchorEnvelope := signedEnvelope{Payload: base64.StdEncoding.EncodeToString(anchorPayload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, anchorPayload))}
	for _, tc := range []struct {
		name, target string
		status       int
		envelope     signedEnvelope
	}{
		{"manifest", "/v2/update", 200, manifestEnvelope},
		{"manifest_absent", "/v2/update", 204, signedEnvelope{}},
		{"manifest_invalid", "/v2/update", 503, signedEnvelope{}},
		{"anchor", "/v2/update/anchor", 200, anchorEnvelope},
		{"anchor_absent", "/v2/update/anchor", 204, signedEnvelope{}},
		{"anchor_invalid", "/v2/update/anchor", 204, signedEnvelope{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifestPath := filepath.Join(directory, "community-linux-update.json")
			anchorPath := filepath.Join(directory, "anchor.json")
			for _, path := range []string{manifestPath, anchorPath} {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
			}
			switch tc.name {
			case "manifest":
				writeReadOnlyResponseFixture(t, directory, "community-linux-update.json", manifestEnvelope)
			case "manifest_invalid":
				invalid := manifestEnvelope
				invalid.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				writeReadOnlyResponseFixture(t, directory, "community-linux-update.json", invalid)
			case "anchor":
				writeReadOnlyResponseFixture(t, directory, "anchor.json", anchorEnvelope)
			case "anchor_invalid":
				invalid := anchorEnvelope
				invalid.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				writeReadOnlyResponseFixture(t, directory, "anchor.json", invalid)
			}
			request := httptest.NewRequest("GET", tc.target, nil)
			request.Header.Set("Authorization", "Bearer "+credential)
			response := serveReadOnlyWithBlockedWriter(t, f, request, device)
			requireHTTP(t, response, tc.status)
			if tc.status == http.StatusOK {
				var actual signedEnvelope
				if err := json.Unmarshal(response.Body.Bytes(), &actual); err != nil || actual != tc.envelope {
					t.Fatal("signed response changed after transaction ended", err)
				}
				payload, e1 := base64.StdEncoding.DecodeString(actual.Payload)
				signature, e2 := base64.StdEncoding.DecodeString(actual.Signature)
				if e1 != nil || e2 != nil || !ed25519.Verify(f.a.config.UpdatePublicKey, payload, signature) {
					t.Fatal("response did not retain its verified signature", e1, e2)
				}
			} else if tc.status == http.StatusNoContent && response.Body.Len() != 0 {
				t.Fatal("absent update response acquired a body")
			} else if tc.status == http.StatusServiceUnavailable && !strings.Contains(response.Body.String(), `"release_invalid"`) {
				t.Fatal("invalid signed release lost its retryable error")
			}
		})
	}
}

func TestAssociationGETEndsTransactionBeforeEscapedBoundResponseIO(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	credential, token := randomToken(), randomToken()
	hostname, organization := `<synthetic & "host">`, `<Synthetic & "Organization">`
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status)
 VALUES($1,$2,'synthetic-alias','test','0.2.0','approved') RETURNING id`, f.org, hash(credential)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	sealed, err := f.a.sealIdentity(f.org, "device-name:"+device, hostname)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `UPDATE devices SET hostname_ciphertext=$1 WHERE id=$2`, sealed, device); err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `UPDATE organizations SET name=$1 WHERE id=$2`, organization, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `INSERT INTO device_association_requests(organization_id,device_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '10 minutes')`, f.org, device, hash(token)); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/auth/device?token="+url.QueryEscape(token), nil)
	response := serveReadOnlyWithBlockedWriter(t, f, request, device)
	requireHTTP(t, response, http.StatusOK)
	body := response.Body.String()
	if !strings.Contains(body, "Installation: "+html.EscapeString(hostname)) || !strings.Contains(body, "Organization: "+html.EscapeString(organization)) || strings.Contains(body, hostname) || strings.Contains(body, organization) {
		t.Fatal("association page did not retain the escaped original machine and organization names")
	}
	if response.Header().Get("Referrer-Policy") != "strict-origin" || response.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(response.Header().Get("Content-Security-Policy"), "base-uri 'none'; frame-ancestors 'none'") {
		t.Fatal("association response lost its browser protections")
	}
	var confirmation *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == f.a.cookieName("association") {
			confirmation = cookie
		}
	}
	if confirmation == nil || len(confirmation.Value) != 43 || confirmation.MaxAge != 600 || !confirmation.HttpOnly || confirmation.Path != "/" || confirmation.SameSite != http.SameSiteLaxMode || confirmation.Secure != f.a.browserSecure() {
		t.Fatal("association response lost its ten-minute browser binding")
	}
	if !strings.Contains(body, `name="token" value="`+token+`"`) || !strings.Contains(body, `name="confirmation" value="`+confirmation.Value+`"`) {
		t.Fatal("association form lost its exact one-use token or confirmation binding")
	}
	form := url.Values{"token": {token}, "confirmation": {confirmation.Value}}
	for _, bound := range []bool{false, true} {
		post := httptest.NewRequest("POST", "/auth/device", strings.NewReader(form.Encode()))
		post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		post.Header.Set("Origin", f.a.browserOrigin())
		if bound {
			post.AddCookie(confirmation)
		}
		out := httptest.NewRecorder()
		f.a.Handler().ServeHTTP(out, post)
		if !bound {
			requireHTTP(t, out, http.StatusForbidden)
			continue
		}
		requireHTTP(t, out, http.StatusFound)
		authorize, err := url.Parse(out.Header().Get("Location"))
		if err != nil || authorize.Query().Get("prompt") != "select_account" || len(authorize.Query().Get("state")) != 43 {
			t.Fatal("bound association did not retain the identity-provider redirect", err)
		}
		var storedOrg, storedDevice string
		var storedHash []byte
		if err = f.admin.QueryRow(ctx, `SELECT association_org::text,association_device::text,association_hash FROM login_attempts WHERE state_hash=$1 AND expires_at>now() AND expires_at<=now()+interval '10 minutes'`, hash(authorize.Query().Get("state"))).Scan(&storedOrg, &storedDevice, &storedHash); err != nil || storedOrg != f.org || storedDevice != device || !bytes.Equal(storedHash, hash(token)) {
			t.Fatal("bound POST did not commit the exact pending association", err)
		}
	}
}
