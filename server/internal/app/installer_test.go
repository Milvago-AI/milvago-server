package app

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func installerBundleFixture(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	t.Setenv("MILVAGO_INSTALLER_DIRECTORY", directory)
	for _, platform := range []string{"windows", "linux"} {
		extension := ".msi"
		if platform == "linux" {
			extension = ".tar.gz"
		}
		name := "synthetic-installer" + extension
		data := []byte("synthetic installer fixture; never a distributable package")
		digest := sha256.Sum256(data)
		manifest, _ := json.Marshal(InstallerBundle{Version: "0.3.0", Artifact: name, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(data))})
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, Edition+"-"+platform+".json"), manifest, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

func TestInstallerReleaseValidation(t *testing.T) {
	directory := installerBundleFixture(t)
	bundle, path, err := installerBundle("windows")
	if err != nil || bundle.Version != "0.3.0" || filepath.Dir(path) != directory {
		t.Fatal("valid bundle unavailable", err)
	}
	if _, _, err = installerBundle("unknown"); err == nil {
		t.Fatal("unknown platform accepted")
	}
	if err = os.WriteFile(path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = installerBundle("windows"); err == nil {
		t.Fatal("tampered artifact accepted")
	}
	bundle.Artifact = "../synthetic.msi"
	raw, _ := json.Marshal(bundle)
	os.WriteFile(filepath.Join(directory, Edition+"-windows.json"), raw, 0600)
	if _, _, err = installerBundle("windows"); err == nil {
		t.Fatal("artifact path traversal accepted")
	}
	t.Setenv("MILVAGO_INSTALLER_DIRECTORY", "")
	if _, err = installerRelease("linux"); err == nil {
		t.Fatal("missing release directory accepted")
	}
}

// The memoized digest is served only while the artifact's (path, size, mtime)
// is exactly what it was: a same-size rewrite keeps the answer, a touched mtime
// forces the re-hash that exposes the corruption, and a removed artifact fails
// on the stat that still runs on every call.
func TestInstallerBundleMemoization(t *testing.T) {
	installerBundleFixture(t)
	a := &App{}
	_, path, err := a.releaseBundle("windows")
	if err != nil {
		t.Fatal("valid bundle unavailable", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Repeat([]byte{'x'}, len(original))
	if err = os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, _, err = a.releaseBundle("windows"); err != nil {
		t.Fatal("unchanged (size, mtime) did not reuse the memoized digest:", err)
	}
	later := info.ModTime().Add(time.Second)
	if err = os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	if _, _, err = a.releaseBundle("windows"); err == nil {
		t.Fatal("corrupted artifact accepted after its mtime changed")
	}
	if err = os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, _, err = a.releaseBundle("windows"); err != nil {
		t.Fatal("restored artifact refused:", err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err = a.releaseBundle("windows"); err == nil {
		t.Fatal("missing artifact accepted")
	}
}

func TestDeploymentKeyAndBootstrap(t *testing.T) {
	runtimeURL, migrationURL := os.Getenv("TEST_DATABASE_URL"), os.Getenv("TEST_MIGRATION_DATABASE_URL")
	if runtimeURL == "" || migrationURL == "" {
		t.Skip("installer integration requires disposable milvago_test database")
	}
	for _, raw := range []string{runtimeURL, migrationURL} {
		u, e := url.Parse(raw)
		if e != nil || u.Path != "/milvago_test" {
			t.Fatal("installer tests require disposable database named milvago_test")
		}
	}
	installerBundleFixture(t)
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, migrationURL)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	if _, e = admin.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); e != nil {
		t.Fatal(e)
	}
	identity := identityProvider(t)
	block, _ := aes.NewCipher(make([]byte, 32))
	gcm, _ := cipher.NewGCM(block)
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	config := Config{DatabaseURL: runtimeURL, MigrationURL: migrationURL, RuntimeRole: "milvago_runtime", OrganizationName: "Installer test organization", BootstrapEmail: "installer@example.test", AppURL: "http://localhost:4020", Issuer: identity.server.URL, ClientID: "test-console", ClientSecret: "synthetic-secret", SessionCipher: gcm, ContentKeys: testContentKeys(), ContentVersion: 1, SigningKey: key, UpdatePublicKey: key.Public().(ed25519.PublicKey)}
	db, e := OpenDatabase(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	reopened, e := OpenDatabase(ctx, config)
	if e != nil {
		t.Fatal("migration restart", e)
	}
	reopened.Close()
	a, e := New(ctx, config, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	var org string
	if e = admin.QueryRow(ctx, `SELECT id FROM organizations LIMIT 1`).Scan(&org); e != nil {
		t.Fatal(e)
	}
	newSession := func(tenant, role string) (*http.Cookie, string) {
		t.Helper()
		tx, e := tenantTx(ctx, admin, tenant)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		var user string
		if e = tx.QueryRow(ctx, `INSERT INTO users(subject,email,display_name) VALUES($1,'installer@example.test','Synthetic installer account') RETURNING id`, randomToken()).Scan(&user); e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3)`, tenant, user, role); e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec(ctx, `INSERT INTO settings(organization_id) VALUES($1) ON CONFLICT DO NOTHING`, tenant); e != nil {
			t.Fatal(e)
		}
		token, csrf := randomToken(), randomToken()
		if _, e = tx.Exec(ctx, `INSERT INTO sessions(token_hash,user_id,organization_id,csrf_token,encrypted_tokens,mfa,expires_at,identity_expires_at) VALUES($1,$2,$3,$4,$5,true,$6,$6)`, hash(token), user, tenant, csrf, []byte("synthetic-session"), time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
		if e = tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}
		return &http.Cookie{Name: cookieName("session"), Value: token}, csrf
	}
	owner, csrf := newSession(org, "owner")
	// Automatic mode: an instance given BOOTSTRAP_EMAIL never offers the setup wizard.
	t.Run("automatic bootstrap keeps setup closed", func(t *testing.T) {
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/setup", nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"pending":false`) {
			t.Fatalf("setup status in automatic mode: %d %s", w.Code, w.Body.String())
		}
		r := httptest.NewRequest("POST", "/api/setup/session", strings.NewReader(`{"token":"any-token-of-any-length-whatsoever"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", config.AppURL)
		w = httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatalf("setup session in automatic mode answered %d", w.Code)
		}
	})
	call := func(method, path string, body any, cookie *http.Cookie, csrf, bearer string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", config.AppURL)
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		return w
	}
	// The key exists because the organization exists, not because someone asked for a
	// package. Nothing in this test ever creates one.
	provision := func(tenant string) InstallerProvision {
		t.Helper()
		tx, e := tenantTx(ctx, db, tenant)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		p, e := a.installerProvision(ctx, tx, tenant, "windows")
		if e != nil {
			t.Fatal(e)
		}
		if len(p.BootstrapToken) != 43 || p.Edition != Edition || p.Platform != "windows" || p.UpdatePublicKey == "" {
			t.Fatal("deployment provision malformed")
		}
		return p
	}
	read := func(cookie *http.Cookie, token, path string) *DeploymentKey {
		t.Helper()
		w := call("GET", path, nil, cookie, token, "")
		requireHTTP(t, w, 200)
		var response struct {
			Key *DeploymentKey `json:"key"`
		}
		if e = json.Unmarshal(w.Body.Bytes(), &response); e != nil {
			t.Fatal(e)
		}
		return response.Key
	}
	setApproval := func(mode string) {
		t.Helper()
		w := call("GET", "/api/shadow/settings", nil, owner, csrf, "")
		requireHTTP(t, w, 200)
		var current map[string]any
		if e = json.Unmarshal(w.Body.Bytes(), &current); e != nil {
			t.Fatal(e)
		}
		config, _ := current["config"].(map[string]any)
		if config == nil {
			t.Fatal("shadow settings carried no configuration")
		}
		config["enrollment"] = map[string]any{"approval": mode, "cidrs": []string{}}
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": current["revision"], "config": config, "inherit_sections": []string{}}, owner, csrf, ""), 200)
	}
	request := func(id string) installationRequest {
		return installationRequest{InstallationID: id, InstallationSecret: randomToken(), Hostname: "synthetic-workstation", Platform: "windows", Version: "0.3.0", Capabilities: []string{"browser.navigation"}}
	}
	t.Run("a key exists from creation and never leaves in clear", func(t *testing.T) {
		key := read(owner, csrf, "/api/deployment-key")
		if key == nil || key.RotatedAt != nil {
			t.Fatal("organization opened without a deployment key")
		}
		secret := provision(org).BootstrapToken
		if w := call("GET", "/api/deployment-key", nil, owner, csrf, ""); strings.Contains(w.Body.String(), secret) {
			t.Fatal("console API returned the deployment secret")
		}
	})
	t.Run("permissions and configured trust", func(t *testing.T) {
		requireHTTP(t, call("GET", "/api/deployment-key", nil, nil, "", ""), 401)
		reader, readerCSRF := newSession(org, "viewer")
		requireHTTP(t, call("GET", "/api/deployment-key", nil, reader, readerCSRF, ""), 403)
		requireHTTP(t, call("POST", "/api/deployment-key/rotate", map[string]any{}, reader, readerCSRF, ""), 403)
		requireHTTP(t, call("POST", "/api/deployment-key/rotate", map[string]any{}, owner, "wrong", ""), 403)
		a.config.UpdatePublicKey = nil
		requireHTTP(t, call("GET", "/api/installer/windows", nil, owner, csrf, ""), 503)
		a.config.UpdatePublicKey = config.UpdatePublicKey
		requireHTTP(t, call("GET", "/api/installer/solaris", nil, owner, csrf, ""), 400)
	})
	t.Run("installation retry is idempotent and secrets stay sealed", func(t *testing.T) {
		setApproval("automatic")
		token := provision(org).BootstrapToken
		body := request("11111111-1111-4111-8111-111111111111")
		w := call("POST", "/v2/install", body, nil, "", token)
		requireHTTP(t, w, 201)
		var first map[string]string
		json.Unmarshal(w.Body.Bytes(), &first)
		w = call("POST", "/v2/install", body, nil, "", token)
		requireHTTP(t, w, 200)
		var retry map[string]string
		json.Unmarshal(w.Body.Bytes(), &retry)
		if first["credential"] != retry["credential"] || first["device_id"] != retry["device_id"] {
			t.Fatal("retry changed identity")
		}
		requireHTTP(t, call("GET", "/v2/policy", nil, nil, "", first["credential"]), 200)
		// Knowing an installation identifier is not knowing the installation.
		forged := body
		forged.InstallationSecret = randomToken()
		requireHTTP(t, call("POST", "/v2/install", forged, nil, "", token), 401)
		forged = body
		forged.Hostname = "changed-host"
		requireHTTP(t, call("POST", "/v2/install", forged, nil, "", token), 401)
		tx, e := tenantTx(ctx, db, org)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		var sealedToken, sealedCredential, kind string
		if e = tx.QueryRow(ctx, `SELECT p.secret_ciphertext,i.credential_ciphertext,d.kind FROM installer_profiles p JOIN installer_installations i ON i.profile_id=p.id JOIN devices d ON d.id=i.device_id WHERE i.installation_id=$1`, body.InstallationID).Scan(&sealedToken, &sealedCredential, &kind); e != nil {
			t.Fatal(e)
		}
		expected := "browser"
		if Edition == "commercial" {
			expected = "native"
		}
		if kind != expected || strings.Contains(sealedToken, token) || strings.Contains(sealedCredential, first["credential"]) {
			t.Fatal("installation storage or composition invalid")
		}
		tx.Rollback(ctx)
		requireHTTP(t, call("POST", "/api/devices/"+first["device_id"]+"/revoke", map[string]any{}, owner, csrf, ""), 200)
		// A revoked device never recovers its credential, even with a valid key.
		requireHTTP(t, call("POST", "/v2/install", body, nil, "", token), 401)
	})
	t.Run("the MSI path obeys the approval policy", func(t *testing.T) {
		setApproval("manual")
		token := provision(org).BootstrapToken
		body := request("66666666-6666-4666-8666-666666666666")
		w := call("POST", "/v2/install", body, nil, "", token)
		requireHTTP(t, w, 201)
		var created map[string]string
		json.Unmarshal(w.Body.Bytes(), &created)
		tx, e := tenantTx(ctx, db, org)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		var status string
		if e = tx.QueryRow(ctx, `SELECT status FROM devices WHERE id=$1`, created["device_id"]).Scan(&status); e != nil {
			t.Fatal(e)
		}
		if status != "pending" {
			t.Fatal("manual approval bypassed by the MSI path: " + status)
		}
		tx.Rollback(ctx)
		// A device awaiting approval still repairs its installation.
		requireHTTP(t, call("POST", "/v2/install", body, nil, "", token), 200)
		setApproval("automatic")
	})
	t.Run("network rules combine a CIDR with the declared machine domain", func(t *testing.T) {
		setEnrollment := func(enrollment map[string]any) int {
			t.Helper()
			w := call("GET", "/api/shadow/settings", nil, owner, csrf, "")
			requireHTTP(t, w, 200)
			var current map[string]any
			if e := json.Unmarshal(w.Body.Bytes(), &current); e != nil {
				t.Fatal(e)
			}
			config, _ := current["config"].(map[string]any)
			config["enrollment"] = enrollment
			return call("PUT", "/api/shadow/settings", map[string]any{"revision": current["revision"], "config": config, "inherit_sections": []string{}}, owner, csrf, "").Code
		}
		rule := func(cidr, domain string) map[string]any { return map[string]any{"cidr": cidr, "domain": domain} }
		// A domain never approves without a network, and hostile names are refused.
		for _, rules := range [][]map[string]any{{rule("", "corp.example.com")}, {rule("192.0.2.0/24", "corp;example.com")}, {rule("192.0.2.0/24", strings.Repeat("a", 254))}} {
			if code := setEnrollment(map[string]any{"approval": "network", "cidrs": []string{}, "rules": rules}); code != 400 {
				t.Fatalf("invalid approval rule accepted: %v -> %d", rules, code)
			}
		}
		many := make([]map[string]any, 51)
		for i := range many {
			many[i] = rule("192.0.2.0/24", "")
		}
		if code := setEnrollment(map[string]any{"approval": "network", "cidrs": []string{}, "rules": many}); code != 400 {
			t.Fatalf("51 approval rules accepted: %d", code)
		}
		// httptest requests come from 192.0.2.1.
		if code := setEnrollment(map[string]any{"approval": "network", "cidrs": []string{}, "rules": []map[string]any{rule("192.0.2.0/24", "corp.example.com"), rule("198.51.100.0/24", "")}}); code != 200 {
			t.Fatalf("valid rules refused: %d", code)
		}
		token := provision(org).BootstrapToken
		enrol := func(id string, domains []machineDomain) (int, string) {
			body := request(id)
			body.MachineDomains = domains
			w := call("POST", "/v2/install", body, nil, "", token)
			if w.Code != 201 {
				return w.Code, ""
			}
			var created map[string]string
			json.Unmarshal(w.Body.Bytes(), &created)
			tx, e := tenantTx(ctx, db, org)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback(ctx)
			var status string
			var stored []machineDomain
			if e = tx.QueryRow(ctx, `SELECT status,machine_domains FROM devices WHERE id=$1`, created["device_id"]).Scan(&status, &stored); e != nil {
				t.Fatal(e)
			}
			if len(stored) != len(domains) {
				t.Fatalf("declared domains not kept: %v", stored)
			}
			return w.Code, status
		}
		for _, c := range []struct {
			id, want string
			domains  []machineDomain
		}{
			{"a1111111-1111-4111-8111-111111111111", "approved", []machineDomain{{"ad", "CORP.Example.com"}}},
			{"a2222222-2222-4222-8222-222222222222", "pending", []machineDomain{{"ad", "other.example.com"}}},
			{"a3333333-3333-4333-8333-333333333333", "pending", nil},
			{"a4444444-4444-4444-8444-444444444444", "pending", []machineDomain{{"realm", "corp.example.com.evil.test"}}},
		} {
			if code, status := enrol(c.id, c.domains); code != 201 || status != c.want {
				t.Fatalf("%v: %d %s, want %s", c.domains, code, status, c.want)
			}
		}
		if code, _ := enrol("a5555555-5555-4555-8555-555555555555", []machineDomain{{"workgroup", "corp.example.com"}}); code != 400 {
			t.Fatalf("unknown domain kind accepted: %d", code)
		}
		// A network rule without a domain approves whatever the machine declares.
		if code := setEnrollment(map[string]any{"approval": "network", "cidrs": []string{}, "rules": []map[string]any{rule("192.0.2.0/24", "")}}); code != 200 {
			t.Fatalf("domainless rule refused: %d", code)
		}
		if _, status := enrol("a6666666-6666-4666-8666-666666666666", nil); status != "approved" {
			t.Fatalf("network rule without domain: %s", status)
		}
		setApproval("automatic")
	})
	t.Run("reinstallation distinguishes deletion from revocation", func(t *testing.T) {
		setApproval("manual")
		token := provision(org).BootstrapToken
		body := request("88888888-8888-4888-8888-888888888888")
		w := call("POST", "/v2/install", body, nil, "", token)
		requireHTTP(t, w, 201)
		var device map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &device); err != nil {
			t.Fatal(err)
		}
		probe := reinstallationRequest{DeviceID: device["device_id"], Credential: device["credential"], Nonce: "99999999-9999-4999-8999-999999999999"}
		check := func(t *testing.T, expected string) {
			t.Helper()
			w := call("POST", "/v2/install/reinstallation", probe, nil, "", token)
			requireHTTP(t, w, 200)
			var envelope map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			payload, err := base64.StdEncoding.DecodeString(envelope["payload"])
			if err != nil {
				t.Fatal(err)
			}
			signature, err := base64.StdEncoding.DecodeString(envelope["signature"])
			if err != nil || !ed25519.Verify(a.policyKey(org).Public().(ed25519.PublicKey), payload, signature) {
				t.Fatal("unsigned reinstallation result")
			}
			var result map[string]string
			if err := json.Unmarshal(payload, &result); err != nil {
				t.Fatal(err)
			}
			if result["status"] != expected || result["device_id"] != probe.DeviceID || result["nonce"] != probe.Nonce || result["purpose"] != "milvago/reinstallation/v1" {
				t.Fatal("wrong confirmation", result)
			}
		}
		check(t, "present")
		requireHTTP(t, call("POST", "/v2/install/reinstallation", probe, nil, "", randomToken()), 401)
		forged := probe
		forged.Credential = randomToken()
		requireHTTP(t, call("POST", "/v2/install/reinstallation", forged, nil, "", token), 401)
		requireHTTP(t, call("POST", "/api/devices/"+probe.DeviceID+"/revoke", map[string]any{}, owner, csrf, ""), 200)
		check(t, "revoked")
		requireHTTP(t, call("POST", "/v2/install", body, nil, "", token), 401)
		// Deleting a device erases its history: a fresh second factor first.
		requireHTTP(t, call("DELETE", "/api/devices/"+probe.DeviceID, nil, owner, csrf, ""), 403)
		if _, e := admin.Exec(ctx, `UPDATE sessions SET mfa=true,mfa_verified_at=clock_timestamp() WHERE token_hash=$1`, hash(owner.Value)); e != nil {
			t.Fatal(e)
		}
		requireHTTP(t, call("DELETE", "/api/devices/"+probe.DeviceID, nil, owner, csrf, ""), 200)
		check(t, "deleted")
		// Deletion removes the former installation record. A new authorized
		// enrollment still obeys manual approval and is idempotent on retry.
		body.InstallationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		w = call("POST", "/v2/install", body, nil, "", token)
		requireHTTP(t, w, 201)
		var replacement map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &replacement); err != nil {
			t.Fatal(err)
		}
		if replacement["device_id"] == probe.DeviceID {
			t.Fatal("deleted identity reused")
		}
		requireHTTP(t, call("GET", "/v2/policy", nil, nil, "", replacement["credential"]), 401)
		requireHTTP(t, call("POST", "/v2/install", body, nil, "", token), 200)
		setApproval("automatic")
	})
	t.Run("rotation and revocation invalidate distributed installers", func(t *testing.T) {
		before := provision(org).BootstrapToken
		requireHTTP(t, call("POST", "/api/deployment-key/rotate", map[string]any{}, owner, csrf, ""), 200)
		after := provision(org).BootstrapToken
		if before == after {
			t.Fatal("rotation reused the secret")
		}
		body := request("33333333-3333-4333-8333-333333333333")
		requireHTTP(t, call("POST", "/v2/install", body, nil, "", before), 401)
		w := call("POST", "/v2/install", body, nil, "", after)
		requireHTTP(t, w, 201)
		var device map[string]string
		json.Unmarshal(w.Body.Bytes(), &device)
		// A rotation must not orphan an installation the previous key created: a
		// repair is recovered by the identity the agent chose, not by the key.
		requireHTTP(t, call("POST", "/api/deployment-key/rotate", map[string]any{}, owner, csrf, ""), 200)
		third := provision(org).BootstrapToken
		w = call("POST", "/v2/install", body, nil, "", third)
		requireHTTP(t, w, 200)
		var repaired map[string]string
		json.Unmarshal(w.Body.Bytes(), &repaired)
		if repaired["device_id"] != device["device_id"] || repaired["credential"] != device["credential"] {
			t.Fatal("rotation orphaned an existing installation")
		}
		if key := read(owner, csrf, "/api/deployment-key"); key == nil || key.RotatedAt == nil {
			t.Fatal("rotation left no live key, or did not record when it happened")
		}
		requireHTTP(t, call("POST", "/api/deployment-key/revoke", map[string]any{}, owner, csrf, ""), 200)
		if read(owner, csrf, "/api/deployment-key") != nil {
			t.Fatal("revoked key still reported")
		}
		// A revocation that the next restart undoes is not a revocation: the console
		// has just told the administrator no installation is possible until they act.
		if e = a.ensureDeploymentKeys(ctx); e != nil {
			t.Fatal(e)
		}
		if read(owner, csrf, "/api/deployment-key") != nil {
			t.Fatal("a restart reissued a deliberately revoked key")
		}
		requireHTTP(t, call("POST", "/v2/install", request("44444444-4444-4444-8444-444444444444"), nil, "", third), 401)
		requireHTTP(t, call("GET", "/api/installer/windows", nil, owner, csrf, ""), 409)
		// Devices already installed are untouched by a revocation.
		requireHTTP(t, call("GET", "/v2/policy", nil, nil, "", device["credential"]), 200)
		requireHTTP(t, call("POST", "/api/deployment-key/rotate", map[string]any{}, owner, csrf, ""), 200)
	})
	t.Run("force RLS and isolation between organizations", func(t *testing.T) {
		var count int
		if e = db.QueryRow(ctx, `SELECT count(*) FROM installer_profiles`).Scan(&count); e != nil || count != 0 {
			t.Fatal("unscoped installer read", count, e)
		}
		if e = db.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relname IN ('installer_profiles','installer_installations') AND relrowsecurity AND relforcerowsecurity`).Scan(&count); e != nil || count != 2 {
			t.Fatal("installer RLS not forced", e)
		}
		if Edition != "commercial" {
			return
		}
		w := call("POST", "/api/organizations", map[string]any{"name": "Synthetic child organization", "parent_id": org}, owner, csrf, "")
		requireHTTP(t, w, 201)
		var created Organization
		if e = json.Unmarshal(w.Body.Bytes(), &created); e != nil {
			t.Fatal(e)
		}
		other := created.ID
		if other == "" {
			t.Fatal("organization created without an identifier")
		}
		if provision(org).BootstrapToken == provision(other).BootstrapToken {
			t.Fatal("organizations share a deployment key")
		}
		childSession, childCSRF := newSession(other, "owner")
		if key := read(childSession, childCSRF, "/api/deployment-key"); key == nil {
			t.Fatal("child organization opened without a key")
		}
		// A member of the child has no standing over the parent, by either route.
		requireHTTP(t, call("GET", "/api/organizations/"+org+"/deployment-key", nil, childSession, childCSRF, ""), 403)
		requireHTTP(t, call("POST", "/api/organizations/"+org+"/deployment-key/rotate", map[string]any{}, childSession, childCSRF, ""), 403)
		// The parent owner reaches the child without switching session into it, and can
		// act on it: reading was never the hard part, and a key that cannot be
		// withdrawn from the page that shows it is not an incident-response tool.
		if key := read(owner, csrf, "/api/organizations/"+other+"/deployment-key"); key == nil {
			t.Fatal("parent owner cannot read the child key")
		}
		childToken := provision(other).BootstrapToken
		requireHTTP(t, call("POST", "/api/organizations/"+other+"/deployment-key/rotate", map[string]any{}, owner, csrf, ""), 200)
		if provision(other).BootstrapToken == childToken {
			t.Fatal("rotating the child from the parent page changed nothing")
		}
		if key := read(owner, csrf, "/api/deployment-key"); key == nil {
			t.Fatal("acting on the child disturbed the parent key")
		}
		requireHTTP(t, call("POST", "/api/organizations/"+other+"/deployment-key/revoke", map[string]any{}, owner, csrf, ""), 200)
		if read(owner, csrf, "/api/organizations/"+other+"/deployment-key") != nil {
			t.Fatal("the child key survived a revocation from the parent page")
		}
		tx, e := tenantTx(ctx, db, other)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		if _, e = a.installerProvision(ctx, tx, org, "windows"); e == nil {
			t.Fatal("child transaction read the parent key")
		}
	})
}
