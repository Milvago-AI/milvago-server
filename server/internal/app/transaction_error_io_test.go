package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTransactionErrorDevice(t *testing.T) (*observabilityFixture, string, string) {
	t.Helper()
	f := newObservabilityFixture(t)
	credential := randomToken()
	var device string
	if err := f.admin.QueryRow(context.Background(), `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,kind,status,last_seen)
 VALUES($1,$2,'synthetic-error-device','linux','0.2.0','browser','approved',NULL) RETURNING id`, f.org, hash(credential)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	return f, device, credential
}

func TestHeartbeatValidationErrorsEndTransactionBeforeIO(t *testing.T) {
	f, device, credential := newTransactionErrorDevice(t)
	for _, tc := range []struct {
		name, message string
		body          any
	}{
		{"collector_health", "Invalid collector health.", map[string]any{"collector_health": []CollectorHealth{{Tool: "synthetic-invalid", State: "synthetic-invalid"}}}},
		{"detector_batches", "Too many detector batches.", map[string]any{"detector_health": make([]DetectorBatch, 9)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest("POST", "/v2/heartbeat", bytes.NewReader(raw))
			request.Header.Set("Authorization", "Bearer "+credential)
			request.Header.Set("Content-Type", "application/json")
			response := serveReadOnlyWithBlockedWriter(t, f, request, device)
			requireHTTP(t, response, http.StatusBadRequest)
			var actual map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &actual); err != nil || actual["error"] != "invalid_request" || actual["message"] != tc.message {
				t.Fatal("validation error changed", err)
			}
			var lastSeen *time.Time
			var version string
			if err = f.admin.QueryRow(context.Background(), `SELECT last_seen,version FROM devices WHERE id=$1`, device).Scan(&lastSeen, &version); err != nil || lastSeen != nil || version != "0.2.0" {
				t.Fatal("rejected heartbeat persisted device state", err)
			}
			var batches int
			if err = f.admin.QueryRow(context.Background(), `SELECT count(*) FROM detector_health WHERE organization_id=$1 AND device_id=$2`, f.org, device).Scan(&batches); err != nil || batches != 0 {
				t.Fatal("rejected heartbeat persisted detector state", err)
			}
		})
	}
}

func TestUpdateArtifactErrorsReleaseOwnedResourcesBeforeIO(t *testing.T) {
	f, device, credential := newTransactionErrorDevice(t)
	directory := t.TempDir()
	t.Setenv("MILVAGO_INSTALLER_DIRECTORY", directory)
	call := func(t *testing.T, digest string, whileBlocked ...func()) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest("GET", "/v2/update/artifact/"+digest, nil)
		request.Header.Set("Authorization", "Bearer "+credential)
		return serveReadOnlyWithBlockedWriter(t, f, request, device, whileBlocked...)
	}
	t.Run("missing_offer", func(t *testing.T) {
		response := call(t, strings.Repeat("a", 64))
		requireHTTP(t, response, http.StatusNotFound)
		if !strings.Contains(response.Body.String(), `"not_found"`) || !strings.Contains(response.Body.String(), "No matching authorized release.") {
			t.Fatal("missing artifact changed its error")
		}
	})
	config := defaultShadowConfig()
	config.Operations.Updates.Enabled = true
	config.Operations.Updates.Percentage = 100
	rawConfig, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(context.Background(), `INSERT INTO shadow_settings(organization_id,configuration) VALUES($1,$2)
 ON CONFLICT(organization_id) DO UPDATE SET configuration=excluded.configuration,revision=nextval('shadow_revision')`, f.org, rawConfig); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{27}, 32))
	f.a.config.UpdatePublicKey = key.Public().(ed25519.PublicKey)
	artifact := []byte("synthetic artifact admission fixture")
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
	writeReadOnlyResponseFixture(t, directory, "community-linux-update.json", signedEnvelope{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))})
	t.Run("download_slots_busy", func(t *testing.T) {
		if len(artifactSlots) != 0 {
			t.Fatal("artifact fixture requires initially unused global slots")
		}
		reserved := 0
		defer func() {
			for reserved > 0 {
				select {
				case <-artifactSlots:
					reserved--
				default:
					t.Error("fixture's reserved artifact slots disappeared")
					return
				}
			}
		}()
		for reserved < cap(artifactSlots) {
			select {
			case artifactSlots <- struct{}{}:
				reserved++
			default:
				t.Fatal("could not reserve the fixture's artifact slots")
			}
		}
		response := call(t, sha, func() {
			if _, owned := artifactHolders.Load(device); owned {
				t.Fatal("busy artifact response retained its own device holder during I/O")
			}
			if len(artifactSlots) != reserved {
				t.Fatal("busy response released another request's artifact slot")
			}
		})
		requireHTTP(t, response, http.StatusServiceUnavailable)
		if !strings.Contains(response.Body.String(), `"download_busy"`) || !strings.Contains(response.Body.String(), "Try the release download again shortly.") {
			t.Fatal("busy artifact changed its retryable error")
		}
	})
}
