package app

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func installerBundle(platform string) (InstallerBundle, string, error) {
	return installerBundleDigest(platform, nil)
}

func installerRelease(platform string) (string, error) {
	bundle, _, err := installerBundle(platform)
	return bundle.Version, err
}

// This profile runs a real Linux package builder and delegates Windows bootstrap
// to the host through a disposable directory. No production session/key is read.
func TestInstallerServedRelease(t *testing.T) {
	if os.Getenv("MILVAGO_REQUIRE_INSTALLERS") != "1" {
		t.Skip("run scripts/qualify-installers.mjs for the required real MSI profile")
	}
	runtimeURL, migrationURL := os.Getenv("TEST_DATABASE_URL"), os.Getenv("TEST_MIGRATION_DATABASE_URL")
	for _, raw := range []string{runtimeURL, migrationURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Path != "/milvago_test" || u.Hostname() != "database" {
			t.Fatal("required installer profile needs its isolated Docker milvago_test database")
		}
	}
	output := os.Getenv("TEST_INSTALLER_DIRECTORY")
	origin, err := url.Parse(os.Getenv("TEST_INSTALLER_ORIGIN"))
	if err != nil || origin.Scheme != "http" || origin.Hostname() != "127.0.0.1" || origin.Port() == "" || output != "/qualification" {
		t.Fatal("required installer profile has invalid loopback origin or evidence mount")
	}
	if _, err = os.Stat("/usr/bin/msiinfo"); err != nil {
		t.Fatal("real MSI verifier required")
	}
	bundle, source, err := installerBundle("windows")
	if err != nil {
		t.Fatal("real release manifest/artifact required", err)
	}
	header, err := os.ReadFile(source)
	if err != nil || len(header) < 8 || !bytes.Equal(header[:8], []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}) {
		t.Fatal("release is not a real MSI")
	}
	header = nil

	// Compare every extracted payload file: server provisioning may only alter its
	// dedicated Binary stream, never the packaged scripts or release executables.
	extract := func(t *testing.T, msi string) map[string]string {
		t.Helper()
		directory := t.TempDir()
		if err := exec.Command("/usr/bin/msiextract", "-C", directory, msi).Run(); err != nil {
			t.Fatal("real MSI payload extraction failed", err)
		}
		files := map[string]string{}
		err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			info, e := entry.Info()
			if e != nil {
				return e
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("non-regular MSI payload")
			}
			data, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			digest := sha256.Sum256(data)
			relative, e := filepath.Rel(directory, path)
			if e != nil {
				return e
			}
			files[relative] = hex.EncodeToString(digest[:])
			return nil
		})
		if err != nil || len(files) < 8 {
			t.Fatal("MSI payload observations missing", err)
		}
		return files
	}
	sourceFiles := extract(t, source)
	agentName := "milvago-browser-agent.exe"
	if Edition == "commercial" {
		agentName = "milvago-commercial-bridge.exe"
	}
	agentBytes, err := os.ReadFile(filepath.Join(output, Edition+"-agent.exe"))
	if err != nil {
		t.Fatal(err)
	}
	agentHash := sha256.Sum256(agentBytes)
	agentMatches := 0
	for name, digest := range sourceFiles {
		if filepath.Base(name) == agentName && digest == hex.EncodeToString(agentHash[:]) {
			agentMatches++
		}
	}
	if agentMatches != 1 {
		t.Fatal("host release executable differs from the one embedded in the actual MSI")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, migrationURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err = admin.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public"); err != nil {
		t.Fatal(err)
	}
	identity := identityProvider(t)
	block, _ := aes.NewCipher(make([]byte, 32))
	gcm, _ := cipher.NewGCM(block)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{DatabaseURL: runtimeURL, MigrationURL: migrationURL, RuntimeRole: "milvago_runtime",
		OrganizationName: "Installer verification synthetic organization", BootstrapEmail: "installer@example.test",
		AppURL: origin.String(), Issuer: identity.server.URL, ClientID: "test-console", ClientSecret: "synthetic-secret",
		SessionCipher: gcm, ContentKeys: testContentKeys(), ContentVersion: 1, SigningKey: key, UpdatePublicKey: key.Public().(ed25519.PublicKey)}
	db, err := OpenDatabase(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a, err := New(ctx, config, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "0.0.0.0:4020")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(a.Handler())
	server.Listener = listener
	server.Start()
	defer server.Close()
	var root string
	if err = admin.QueryRow(ctx, "SELECT id FROM organizations LIMIT 1").Scan(&root); err != nil {
		t.Fatal(err)
	}
	session := func(t *testing.T, org string) (*http.Cookie, string) {
		tx, e := tenantTx(ctx, admin, org)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		var user string
		if e = tx.QueryRow(ctx, "INSERT INTO users(subject,email,display_name) VALUES($1,'installer@example.test','Synthetic installer account') RETURNING id", randomToken()).Scan(&user); e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec(ctx, "INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')", org, user); e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec(ctx, "INSERT INTO settings(organization_id) VALUES($1) ON CONFLICT DO NOTHING", org); e != nil {
			t.Fatal(e)
		}
		token, csrf := randomToken(), randomToken()
		if _, e = tx.Exec(ctx, "INSERT INTO sessions(token_hash,user_id,organization_id,csrf_token,encrypted_tokens,mfa,expires_at,identity_expires_at) VALUES($1,$2,$3,$4,$5,true,$6,$6)", hash(token), user, org, csrf, []byte("synthetic-session"), time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
		if e = tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}
		return &http.Cookie{Name: cookieName("session"), Value: token}, csrf
	}
	owner, csrf := session(t, root)
	t.Run("linux_download", func(t *testing.T) {
		for _, tool := range []string{"/usr/bin/rpm", "/usr/bin/rpm2cpio", "/usr/bin/cpio"} {
			if info, e := os.Stat(tool); e != nil || info.Mode()&0111 == 0 {
				t.Fatal("required RPM qualification tool unavailable", tool)
			}
		}
		linuxBundle, linuxSource, e := installerBundle("linux")
		if e != nil || linuxBundle.Version != bundle.Version {
			t.Fatal("real Linux release missing or differs from Windows version", e)
		}
		payload := t.TempDir()
		if e = extractInstallerPayload(linuxSource, payload); e != nil {
			t.Fatal("real Linux source extraction failed", e)
		}
		if e = validateInstallerPayload(payload, Edition); e != nil {
			t.Fatal("real Linux source edition boundary failed", e)
		}
		req, e := http.NewRequest("GET", server.URL+"/api/installer/linux", nil)
		if e != nil {
			t.Fatal(e)
		}
		req.AddCookie(owner)
		response, e := (&http.Client{Timeout: 100 * time.Second}).Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 || response.Header.Get("Content-Type") != "application/x-rpm" || response.Header.Get("X-Milvago-Installer-Version") != linuxBundle.Version || !strings.Contains(response.Header.Get("Cache-Control"), "no-store") {
			t.Fatal("real RPM HTTP download failed", response.StatusCode)
		}
		data, e := io.ReadAll(io.LimitReader(response.Body, 128*1024*1024+1))
		if e != nil || len(data) < 4 || len(data) > 128*1024*1024 || !bytes.Equal(data[:4], []byte{0xed, 0xab, 0xee, 0xdb}) {
			t.Fatal("real RPM download invalid")
		}
		rpmPath := filepath.Join(t.TempDir(), "download.rpm")
		if e = os.WriteFile(rpmPath, data, 0600); e != nil {
			t.Fatal(e)
		}
		version, e := exec.Command("/usr/bin/rpm", "-qp", "--queryformat", "%{VERSION}", rpmPath).Output()
		if e != nil || string(version) != linuxBundle.Version {
			t.Fatal("downloaded RPM version mismatch", e)
		}
		archive, e := exec.Command("/usr/bin/rpm2cpio", rpmPath).Output()
		if e != nil || len(archive) == 0 || int64(len(archive)) > installerBundleLimit {
			t.Fatal("downloaded RPM payload missing", e)
		}
		list := exec.Command("/usr/bin/cpio", "-it", "--quiet")
		list.Stdin = bytes.NewReader(archive)
		listing, e := list.Output()
		if e != nil {
			t.Fatal("RPM payload listing failed", e)
		}
		entries := map[string]string{}
		for _, entry := range strings.Split(strings.TrimSpace(string(listing)), "\n") {
			// rpmbuild wrote ./opt/..., the in-process builder writes /opt/...: both name the same file.
			name := strings.TrimPrefix(strings.TrimPrefix(entry, "."), "/")
			clean := filepath.Clean(name)
			if name == "" || filepath.IsAbs(name) || clean != name || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\:\x00") || entries[name] != "" {
				t.Fatal("unsafe or duplicate RPM payload path")
			}
			entries[name] = entry
			if Edition == "community" && (strings.Contains(name, "milvago-commercial") || strings.Contains(name, "milvago-collector") || strings.Contains(name, "milvago-model-filter") || strings.Contains(name, "register-model-filter") || strings.Contains(name, "milvago_filter")) {
				t.Fatal("native Enterprise component in Community RPM")
			}
		}
		names := []string{"milvago-browser-agent", "milvago-updater"}
		if Edition == "commercial" {
			names = []string{"milvago-commercial-bridge", "milvago-updater", "milvago-collector", "milvago-model-filter"}
		}
		observed := 0
		for _, name := range names {
			entry := "opt/milvago-" + Edition + "/" + name
			if entries[entry] == "" {
				t.Fatal("required RPM executable absent", name)
			}
			// Extract to stdout only: no archive-controlled filesystem path is written.
			extract := exec.Command("/usr/bin/cpio", "-i", "--to-stdout", "--quiet", entries[entry])
			extract.Stdin = bytes.NewReader(archive)
			got, e := extract.Output()
			if e != nil {
				t.Fatal("RPM executable extraction failed", e)
			}
			want, e := os.ReadFile(filepath.Join(payload, name))
			if e != nil || len(want) == 0 || !bytes.Equal(got, want) {
				t.Fatal("RPM executable differs from final TAR", name, e)
			}
			observed++
		}
		digest := sha256.Sum256(data)
		t.Logf("linux HTTP downloads=1 payloads=%d version=%s rpm_sha256=%s", observed, linuxBundle.Version, hex.EncodeToString(digest[:]))
	})
	call := func(t *testing.T, method, path string, body any, cookie *http.Cookie, token string) *httptest.ResponseRecorder {
		raw, e := json.Marshal(body)
		if e != nil {
			t.Fatal(e)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", config.AppURL)
		r.Header.Set("X-CSRF-Token", token)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		return w
	}
	// Each response is tied to a fresh sequence number; stale marker files cannot
	// make a bootstrap pass. The host records only exit status, never credentials.
	step := 0
	bootstrap := func(t *testing.T, msi, state, hostname, binaryEdition string, success bool) {
		step++
		request := map[string]any{"step": step, "edition": Edition, "binary_edition": binaryEdition, "msi": msi, "state": state, "hostname": hostname, "success": success}
		raw, _ := json.Marshal(request)
		name := filepath.Join(output, fmt.Sprintf("%s-%02d.request.json", Edition, step))
		if err = os.WriteFile(name+".tmp", raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(name+".tmp", name); err != nil {
			t.Fatal(err)
		}
		response := strings.Replace(name, ".request.json", ".response.json", 1)
		deadline := time.Now().Add(45 * time.Second)
		for {
			raw, e := os.ReadFile(response)
			if e == nil {
				var result struct {
					Step int
					OK   bool
				}
				if json.Unmarshal(raw, &result) != nil || result.Step != step || !result.OK {
					t.Fatal("real Windows bootstrap did not satisfy expected result")
				}
				return
			}
			if !os.IsNotExist(e) || time.Now().After(deadline) {
				t.Fatal("required Windows bootstrap observation missing")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	// A generic update cannot enroll a fresh identity.
	generic := Edition + "-generic.msi"
	if err = copyInstallerFile(source, filepath.Join(output, generic)); err != nil {
		t.Fatal(err)
	}
	bootstrap(t, generic, Edition+"-generic-state", "synthetic-generic", Edition, false)
	for index, mode := range []string{"automatic", "manual"} {
		t.Run(mode, func(t *testing.T) {
			org, cookie, token := root, owner, csrf
			if Edition == "commercial" && mode == "manual" {
				w := call(t, "POST", "/api/organizations", map[string]any{"name": "Synthetic installer child", "parent_id": root}, owner, csrf)
				requireHTTP(t, w, 201)
				var created Organization
				if json.Unmarshal(w.Body.Bytes(), &created) != nil || created.ID == "" {
					t.Fatal("missing synthetic child")
				}
				org = created.ID
				cookie, token = session(t, org)
			}
			w := call(t, "GET", "/api/shadow/settings", nil, cookie, token)
			requireHTTP(t, w, 200)
			var current map[string]any
			if json.Unmarshal(w.Body.Bytes(), &current) != nil {
				t.Fatal("settings response invalid")
			}
			settings, ok := current["config"].(map[string]any)
			if !ok {
				t.Fatal("settings missing")
			}
			settings["enrollment"] = map[string]any{"approval": mode, "cidrs": []string{}}
			requireHTTP(t, call(t, "PUT", "/api/shadow/settings", map[string]any{"revision": current["revision"], "config": settings, "inherit_sections": []string{}}, cookie, token), 200)
			tx, e := tenantTx(ctx, db, org)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback(ctx)
			var keyID string
			var beforeUses int
			if e = tx.QueryRow(ctx, "SELECT id,uses FROM installer_profiles WHERE platform IS NULL AND NOT revoked").Scan(&keyID, &beforeUses); e != nil {
				t.Fatal(e)
			}
			tx.Rollback(ctx)
			req, e := http.NewRequest("GET", "http://127.0.0.1:4020/api/installer/windows", nil)
			if e != nil {
				t.Fatal(e)
			}
			req.AddCookie(cookie)
			client := &http.Client{Timeout: 100 * time.Second}
			download, e := client.Do(req)
			if e != nil {
				t.Fatal(e)
			}
			defer download.Body.Close()
			if download.StatusCode != 200 || download.Header.Get("X-Milvago-Installer-Version") != bundle.Version || !strings.Contains(download.Header.Get("Cache-Control"), "no-store") || download.Header.Get("Content-Type") != "application/x-msi" {
				t.Fatal("real MSI download failed", download.StatusCode)
			}
			data, e := io.ReadAll(io.LimitReader(download.Body, 128*1024*1024+1))
			if e != nil || len(data) < 8 || len(data) > 128*1024*1024 || !bytes.Equal(data[:8], []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}) {
				t.Fatal("real MSI response invalid")
			}
			msi := Edition + "-" + mode + ".msi"
			path := filepath.Join(output, msi)
			if e = os.WriteFile(path, data, 0600); e != nil {
				t.Fatal(e)
			}
			digest := sha256.Sum256(data)

			servedFiles := extract(t, path)
			if len(servedFiles) != len(sourceFiles) {
				t.Fatal("served MSI changed payload file count")
			}
			for name, digest := range sourceFiles {
				if servedFiles[name] != digest {
					t.Fatal("served MSI changed release payload", name)
				}
			}
			raw, e := exec.Command("/usr/bin/msiinfo", "extract", path, "Binary.MilvagoProvision").Output()
			if e != nil {
				t.Fatal("cannot inspect served MSI provision", e)
			}
			var provision InstallerProvision
			if json.Unmarshal(raw, &provision) != nil || provision.Edition != Edition || provision.Platform != "windows" || provision.Version != bundle.Version || provision.ProfileID != keyID || provision.ServerURL != config.AppURL || provision.PolicyPublicKey != base64.StdEncoding.EncodeToString(a.policyKey(org).Public().(ed25519.PublicKey)) || provision.UpdatePublicKey != base64.StdEncoding.EncodeToString(config.UpdatePublicKey) || len(provision.BootstrapToken) != 43 {
				t.Fatal("served MSI provision does not match synthetic organization")
			}
			opposite := "commercial"
			if Edition == "commercial" {
				opposite = "community"
			}
			hostname := "synthetic-" + Edition + "-" + mode
			bootstrap(t, msi, Edition+"-"+mode+"-wrong", hostname, opposite, false)
			var deviceID string
			var credentialHash []byte
			for attempt := 0; attempt < 2; attempt++ {
				bootstrap(t, msi, Edition+"-"+mode+"-state", hostname, Edition, true)
				view := call(t, "GET", "/api/devices", nil, cookie, token)
				requireHTTP(t, view, 200)
				var devices struct {
					Items []struct{ ID, Hostname string }
				}
				if e = json.Unmarshal(view.Body.Bytes(), &devices); e != nil {
					t.Fatal("authorized machine projection invalid", e)
				}
				matches, projectedID := 0, ""
				for _, device := range devices.Items {
					if device.Hostname == hostname {
						matches++
						projectedID = device.ID
					}
				}
				if matches != 1 || projectedID == "" {
					t.Fatal("bootstrap must project exactly one named device in target organization", matches)
				}
				tx, e = tenantTx(ctx, db, org)
				if e != nil {
					t.Fatal(e)
				}
				defer tx.Rollback(ctx)
				var count, uses int
				var gotID, status, version, kind, currentKey string
				var gotHash []byte
				if e = tx.QueryRow(ctx, "SELECT count(*) FROM devices WHERE id=$1", projectedID).Scan(&count); e != nil || count != 1 {
					t.Fatal("bootstrap must create exactly one device in target organization", count, e)
				}
				var alias, sealed string
				if e = tx.QueryRow(ctx, "SELECT id,credential_hash,status,version,kind,hostname,hostname_ciphertext FROM devices WHERE id=$1", projectedID).Scan(&gotID, &gotHash, &status, &version, &kind, &alias, &sealed); e != nil {
					t.Fatal(e)
				}
				plaintext, openErr := a.openShadow(org, "device-name:"+gotID, sealed)
				if openErr != nil || string(plaintext) != hostname || alias != deviceAlias(gotID) || sealed == "" || strings.Contains(sealed, hostname) {
					t.Fatal("machine name must be recoverable only from its sealed storage")
				}
				if e = tx.QueryRow(ctx, "SELECT count(*) FROM devices WHERE hostname=$1", hostname).Scan(&count); e != nil || count != 0 {
					t.Fatal("machine name stored in plaintext", e)
				}
				expectedStatus := "approved"
				if mode == "manual" {
					expectedStatus = "pending"
				}
				expectedKind := "browser"
				if Edition == "commercial" {
					expectedKind = "native"
				}
				if status != expectedStatus || version != bundle.Version || kind != expectedKind {
					t.Fatal("real bootstrap did not honor approval/version/edition", status, version, kind)
				}
				if attempt == 0 {
					deviceID, credentialHash = gotID, gotHash
				} else if deviceID != gotID || !bytes.Equal(credentialHash, gotHash) {
					t.Fatal("repair changed existing identity")
				}
				if e = tx.QueryRow(ctx, "SELECT id,uses FROM installer_profiles WHERE platform IS NULL AND NOT revoked").Scan(&currentKey, &uses); e != nil || currentKey != keyID || uses != beforeUses+1 {
					t.Fatal("bootstrap rotated key or counted retry as new enrollment", e)
				}
				if e = tx.QueryRow(ctx, "SELECT count(*) FROM installer_installations WHERE device_id=$1", gotID).Scan(&count); e != nil || count != 1 {
					t.Fatal("duplicate enrollment", e)
				}
				tx.Rollback(ctx)
			}
			if mode == "manual" {
				requireHTTP(t, call(t, "POST", "/api/devices/"+deviceID+"/approve", map[string]any{}, cookie, token), 200)
				tx, e = tenantTx(ctx, db, org)
				if e != nil {
					t.Fatal(e)
				}
				defer tx.Rollback(ctx)
				var status string
				if e = tx.QueryRow(ctx, "SELECT status FROM devices WHERE id=$1", deviceID).Scan(&status); e != nil || status != "approved" {
					t.Fatal("approval did not reach device", e)
				}
				tx.Rollback(ctx)
			}
			if Edition == "commercial" && index == 1 {
				tx, e = tenantTx(ctx, db, root)
				if e != nil {
					t.Fatal(e)
				}
				defer tx.Rollback(ctx)
				var count int
				if e = tx.QueryRow(ctx, "SELECT count(*) FROM devices WHERE id=$1", deviceID).Scan(&count); e != nil || count != 0 {
					t.Fatal("child enrollment leaked into parent", e)
				}
				tx.Rollback(ctx)
			}
			t.Logf("served MSI %s %s sha256=%s; real bootstrap, approval and identity retry verified", Edition, bundle.Version, hex.EncodeToString(digest[:]))
		})
	}
	t.Logf("source MSI sha256=%s; %d host bootstrap observations required", bundle.SHA256, step)
}
