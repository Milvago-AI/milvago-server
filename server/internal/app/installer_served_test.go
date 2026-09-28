package app

import (
	"archive/zip"
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

	"github.com/jackc/pgx/v5"
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
	profile := requireInstallerTestProfile(t)
	output := profile.output
	bundle, source, sourceFiles := loadInstallerSource(t, output)
	ctx := context.Background()
	setup := newInstallerServerFixture(t, ctx, profile)
	a, config, serverURL, owner := setup.app, setup.config, setup.serverURL, setup.owner
	t.Run("linux_download", func(t *testing.T) { assertLinuxDownload(t, serverURL, owner, bundle.Version) })
	caller := installerCaller{a: a, origin: config.AppURL}
	t.Run("windows_zip_mfa", func(t *testing.T) { assertWindowsPackageMFA(t, ctx, setup, caller) })
	// Each response is tied to a fresh sequence number; stale marker files cannot
	// make a bootstrap pass. The host records only exit status, never credentials.
	observer := &installerBootstrapObserver{output: output}
	// A generic update cannot enroll a fresh identity.
	generic := Edition + "-generic.msi"
	if err := copyInstallerFile(source, filepath.Join(output, generic)); err != nil {
		t.Fatal(err)
	}
	observer.observe(t, generic, "", Edition+"-generic-state", "synthetic-generic", Edition, false)
	fixture := servedInstallerFixture{setup: setup, bundle: bundle, sourceFiles: sourceFiles, output: output, caller: caller, observer: observer}
	for index, mode := range []string{"automatic", "manual"} {
		t.Run(mode, func(t *testing.T) { fixture.assertMode(t, ctx, index, mode) })
	}
	t.Logf("source MSI sha256=%s; %d host bootstrap observations required", bundle.SHA256, observer.step)
}

func assertWindowsPackageMFA(t *testing.T, ctx context.Context, setup installerServerFixture, caller installerCaller) {
	owner, csrf, admin := setup.owner, setup.csrf, setup.admin
	result, err := admin.Exec(ctx, `UPDATE sessions SET mfa_verified_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1`, hash(owner.Value))
	if err != nil || result.RowsAffected() != 1 {
		t.Fatal("could not age the owner session", err)
	}
	defer func() {
		restored, restoreErr := admin.Exec(ctx, `UPDATE sessions SET mfa_verified_at=clock_timestamp() WHERE token_hash=$1`, hash(owner.Value))
		if restoreErr != nil || restored.RowsAffected() != 1 {
			t.Error("could not restore the owner session", restoreErr)
		}
	}()
	stale := caller.call(t, "POST", "/api/installer/windows/package", nil, owner, csrf)
	if stale.Code != 403 || !strings.Contains(stale.Body.String(), "fresh_mfa_required") {
		t.Fatal("stale second factor must block Windows package")
	}
	withoutFactor, token := newInstallerSession(t, ctx, admin, setup.root)
	result, err = admin.Exec(ctx, `UPDATE sessions SET mfa=false, mfa_verified_at=NULL WHERE token_hash=$1`, hash(withoutFactor.Value))
	if err != nil || result.RowsAffected() != 1 {
		t.Fatal("could not remove the synthetic second factor", err)
	}
	packageResponse := caller.call(t, "POST", "/api/installer/windows/package", nil, withoutFactor, token)
	if packageResponse.Code != 200 || packageResponse.Header().Get("Content-Type") != "application/zip" || !strings.Contains(packageResponse.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("account without a second factor could not download ZIP", packageResponse.Code)
	}
}

func extractMSIPayloadFiles(t *testing.T, msi string) map[string]string {
	t.Helper()
	directory := t.TempDir()
	if err := exec.Command("/usr/bin/msiextract", "-C", directory, msi).Run(); err != nil {
		t.Fatal("real MSI payload extraction failed", err)
	}
	files := map[string]string{}
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
		return collectMSIPayloadFile(directory, files, path, entry, walkErr)
	})
	if err != nil || len(files) < 8 {
		t.Fatal("MSI payload observations missing", err)
	}
	return files
}

func collectMSIPayloadFile(directory string, files map[string]string, path string, entry os.DirEntry, walkErr error) error {
	if walkErr != nil {
		return walkErr
	}
	if entry.IsDir() {
		return nil
	}
	info, err := entry.Info()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("non-regular MSI payload")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	relative, err := filepath.Rel(directory, path)
	if err != nil {
		return err
	}
	files[relative] = hex.EncodeToString(digest[:])
	return nil
}

func newInstallerSession(t *testing.T, ctx context.Context, admin *pgxpool.Pool, org string) (*http.Cookie, string) {
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
	if _, e = tx.Exec(ctx, "INSERT INTO sessions(token_hash,user_id,organization_id,csrf_token,encrypted_tokens,mfa,mfa_verified_at,expires_at,identity_expires_at) VALUES($1,$2,$3,$4,$5,true,clock_timestamp(),$6,$6)", hash(token), user, org, csrf, []byte("synthetic-session"), time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	return &http.Cookie{Name: cookieName("session"), Value: token}, csrf
}

type installerCaller struct {
	a      *App
	origin string
}

func (c installerCaller) call(t *testing.T, method, path string, body any, cookie *http.Cookie, token string) *httptest.ResponseRecorder {
	raw, e := json.Marshal(body)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", c.origin)
	r.Header.Set("X-CSRF-Token", token)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	c.a.Handler().ServeHTTP(w, r)
	return w
}

type installerBootstrapObserver struct {
	output string
	step   int
}

func (o *installerBootstrapObserver) observe(t *testing.T, msi, provision, state, hostname, binaryEdition string, success bool) {
	o.step++
	request := map[string]any{"step": o.step, "edition": Edition, "binary_edition": binaryEdition, "msi": msi, "provision": provision, "state": state, "hostname": hostname, "success": success}
	raw, _ := json.Marshal(request)
	name := filepath.Join(o.output, fmt.Sprintf("%s-%02d.request.json", Edition, o.step))
	if err := os.WriteFile(name+".tmp", raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(name+".tmp", name); err != nil {
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
			if json.Unmarshal(raw, &result) != nil || result.Step != o.step || !result.OK {
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

func assertLinuxDownload(t *testing.T, serverURL string, owner *http.Cookie, wantVersion string) {
	linuxBundle, payload := linuxReleasePayload(t, wantVersion)
	data, archive, listing := downloadLinuxRPM(t, serverURL, owner, linuxBundle.Version)
	entries := rpmPayloadEntries(t, listing)
	observed := assertLinuxExecutables(t, archive, entries, payload)
	digest := sha256.Sum256(data)
	t.Logf("linux HTTP downloads=1 payloads=%d version=%s rpm_sha256=%s", observed, linuxBundle.Version, hex.EncodeToString(digest[:]))
}

func linuxReleasePayload(t *testing.T, wantVersion string) (InstallerBundle, string) {
	for _, tool := range []string{"/usr/bin/rpm", "/usr/bin/rpm2cpio", "/usr/bin/cpio"} {
		if info, e := os.Stat(tool); e != nil || info.Mode()&0111 == 0 {
			t.Fatal("required RPM qualification tool unavailable", tool)
		}
	}
	linuxBundle, linuxSource, e := installerBundle("linux")
	if e != nil || linuxBundle.Version != wantVersion {
		t.Fatal("real Linux release missing or differs from Windows version", e)
	}
	payload := t.TempDir()
	if e = extractInstallerPayload(linuxSource, payload); e != nil {
		t.Fatal("real Linux source extraction failed", e)
	}
	if e = validateInstallerPayload(payload, Edition); e != nil {
		t.Fatal("real Linux source edition boundary failed", e)
	}
	return linuxBundle, payload
}

func downloadLinuxRPM(t *testing.T, serverURL string, owner *http.Cookie, version string) ([]byte, []byte, []byte) {
	req, e := http.NewRequest("GET", serverURL+"/api/installer/linux", nil)
	if e != nil {
		t.Fatal(e)
	}
	req.AddCookie(owner)
	response, e := (&http.Client{Timeout: 100 * time.Second}).Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != "application/x-rpm" || response.Header.Get("X-Milvago-Installer-Version") != version || !strings.Contains(response.Header.Get("Cache-Control"), "no-store") {
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
	rpmVersion, e := exec.Command("/usr/bin/rpm", "-qp", "--queryformat", "%{VERSION}", rpmPath).Output()
	if e != nil || string(rpmVersion) != version {
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
	return data, archive, listing
}

func rpmPayloadEntries(t *testing.T, listing []byte) map[string]string {
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
	return entries
}

func assertLinuxExecutables(t *testing.T, archive []byte, entries map[string]string, payload string) int {
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
	return observed
}

type installerTestProfile struct {
	runtimeURL   string
	migrationURL string
	output       string
	origin       *url.URL
}

func requireInstallerTestProfile(t *testing.T) installerTestProfile {
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
	if _, err := os.Stat("/usr/bin/msiinfo"); err != nil {
		t.Fatal("real MSI verifier required")
	}
	return installerTestProfile{runtimeURL: runtimeURL, migrationURL: migrationURL, output: output, origin: origin}
}

func loadInstallerSource(t *testing.T, output string) (InstallerBundle, string, map[string]string) {
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
	sourceFiles := extractMSIPayloadFiles(t, source)
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
	return bundle, source, sourceFiles
}

type installerServerFixture struct {
	admin     *pgxpool.Pool
	db        *pgxpool.Pool
	app       *App
	config    Config
	serverURL string
	root      string
	owner     *http.Cookie
	csrf      string
}

func newInstallerServerFixture(t *testing.T, ctx context.Context, profile installerTestProfile) installerServerFixture {
	runtimeURL, migrationURL, origin := profile.runtimeURL, profile.migrationURL, profile.origin
	admin, err := pgxpool.New(ctx, migrationURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
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
	t.Cleanup(db.Close)
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
	t.Cleanup(server.Close)
	var root string
	if err = admin.QueryRow(ctx, "SELECT id FROM organizations LIMIT 1").Scan(&root); err != nil {
		t.Fatal(err)
	}
	owner, csrf := newInstallerSession(t, ctx, admin, root)
	return installerServerFixture{admin: admin, db: db, app: a, config: config, serverURL: server.URL, root: root, owner: owner, csrf: csrf}
}

type servedInstallerFixture struct {
	setup       installerServerFixture
	bundle      InstallerBundle
	sourceFiles map[string]string
	output      string
	caller      installerCaller
	observer    *installerBootstrapObserver
}

func (x servedInstallerFixture) assertMode(t *testing.T, ctx context.Context, index int, mode string) {
	bundle, observer := x.bundle, x.observer
	state := x.prepareMode(t, ctx, index, mode)
	x.downloadModeMSI(t, &state)
	msi, digest := state.msi, state.digest
	x.assertServedMSI(t, state)
	opposite := "commercial"
	if Edition == "commercial" {
		opposite = "community"
	}
	hostname := "synthetic-" + Edition + "-" + mode
	observer.observe(t, msi, state.provision, Edition+"-"+mode+"-wrong", hostname, opposite, false)
	state.hostname = hostname
	x.assertModeRetry(t, ctx, &state)
	x.assertManualApproval(t, ctx, state)
	x.assertChildIsolation(t, ctx, state)
	t.Logf("served MSI %s %s sha256=%s; real bootstrap, approval and identity retry verified", Edition, bundle.Version, hex.EncodeToString(digest[:]))

}

type installerModeState struct {
	mode           string
	index          int
	org            string
	cookie         *http.Cookie
	token          string
	keyID          string
	beforeUses     int
	msi            string
	provision      string
	path           string
	digest         [32]byte
	hostname       string
	deviceID       string
	credentialHash []byte
}

func (x servedInstallerFixture) prepareMode(t *testing.T, ctx context.Context, index int, mode string) installerModeState {
	admin, db := x.setup.admin, x.setup.db
	root, owner, csrf := x.setup.root, x.setup.owner, x.setup.csrf
	caller := x.caller
	org, cookie, token := root, owner, csrf
	if Edition == "commercial" && mode == "manual" {
		w := caller.call(t, "POST", "/api/organizations", map[string]any{"name": "Synthetic installer child", "parent_id": root}, owner, csrf)
		requireHTTP(t, w, 201)
		var created Organization
		if json.Unmarshal(w.Body.Bytes(), &created) != nil || created.ID == "" {
			t.Fatal("missing synthetic child")
		}
		org = created.ID
		cookie, token = newInstallerSession(t, ctx, admin, org)
	}
	w := caller.call(t, "GET", "/api/shadow/settings", nil, cookie, token)
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
	requireHTTP(t, caller.call(t, "PUT", "/api/shadow/settings", map[string]any{"revision": current["revision"], "config": settings, "inherit_sections": []string{}}, cookie, token), 200)
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
	return installerModeState{mode: mode, index: index, org: org, cookie: cookie, token: token, keyID: keyID, beforeUses: beforeUses}
}

func (x servedInstallerFixture) downloadModeMSI(t *testing.T, state *installerModeState) {
	cookie, mode, bundle, output := state.cookie, state.mode, x.bundle, x.output
	download := x.downloadWindowsPackage(t, cookie, state.token)
	defer download.Body.Close()
	data := readWindowsPackage(t, download.Body)
	archive, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if e != nil || len(archive.File) != 4 {
		t.Fatal("ZIP must contain exactly four files", e)
	}
	files := readWindowsPackageFiles(t, archive)
	assertWindowsPackageReadme(t, files["README.md"])
	msiBytes := files["milvago-windows-installer.msi"]
	if len(msiBytes) < 8 || !bytes.Equal(msiBytes[:8], []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}) {
		t.Fatal("ZIP MSI response invalid")
	}
	msi := Edition + "-" + mode + ".msi"
	path := filepath.Join(output, msi)
	if e = os.WriteFile(path, msiBytes, 0600); e != nil {
		t.Fatal(e)
	}
	state.msi, state.path, state.digest = msi, path, sha256.Sum256(msiBytes)
	assertWindowsPackageScript(t, files["milvago-windows-install.ps1"], bundle)
	state.provision = Edition + "-" + mode + ".json"
	if e = os.WriteFile(filepath.Join(output, state.provision), files["milvago-provision.json"], 0600); e != nil {
		t.Fatal(e)
	}
}

func (x servedInstallerFixture) downloadWindowsPackage(t *testing.T, cookie *http.Cookie, token string) *http.Response {
	t.Helper()
	req, e := http.NewRequest("POST", "http://127.0.0.1:4020/api/installer/windows/package", nil)
	if e != nil {
		t.Fatal(e)
	}
	req.AddCookie(cookie)
	req.Header.Set("Origin", x.setup.config.AppURL)
	req.Header.Set("X-CSRF-Token", token)
	client := &http.Client{Timeout: 100 * time.Second}
	download, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	if download.StatusCode != 200 || download.Header.Get("X-Milvago-Installer-Version") != x.bundle.Version || !strings.Contains(download.Header.Get("Cache-Control"), "no-store") || download.Header.Get("Content-Type") != "application/zip" || !strings.Contains(download.Header.Get("Content-Disposition"), windowsPackageName) {
		download.Body.Close()
		t.Fatal("real ZIP download failed", download.StatusCode)
	}
	return download
}

func readWindowsPackage(t *testing.T, body io.Reader) []byte {
	t.Helper()
	data, e := io.ReadAll(io.LimitReader(body, 129*1024*1024+1))
	if e != nil || len(data) < 4 || len(data) > 129*1024*1024 || !bytes.Equal(data[:2], []byte("PK")) {
		t.Fatal("real ZIP response invalid")
	}
	return data
}

func readWindowsPackageFiles(t *testing.T, archive *zip.Reader) map[string][]byte {
	t.Helper()
	wanted := map[string]bool{"milvago-windows-installer.msi": true, "milvago-windows-install.ps1": true, "milvago-provision.json": true, "README.md": true}
	files := map[string][]byte{}
	for _, entry := range archive.File {
		if !wanted[entry.Name] || files[entry.Name] != nil {
			t.Fatal("unexpected ZIP entry")
		}
		file, openErr := entry.Open()
		if openErr != nil {
			t.Fatal(openErr)
		}
		contents, readErr := io.ReadAll(io.LimitReader(file, 128*1024*1024+1))
		file.Close()
		if readErr != nil || len(contents) > 128*1024*1024 {
			t.Fatal("ZIP entry invalid", readErr)
		}
		files[entry.Name] = contents
	}
	return files
}

func assertWindowsPackageReadme(t *testing.T, contents []byte) {
	t.Helper()
	readme := string(contents)
	for _, instruction := range []string{"-MsiPath .\\milvago-windows-installer.msi", "-ProvisionPath .\\milvago-provision.json", "as Administrator"} {
		if !strings.Contains(readme, instruction) {
			t.Fatal("ZIP README is missing an installation instruction", instruction)
		}
	}
}

func assertWindowsPackageScript(t *testing.T, script []byte, bundle InstallerBundle) {
	t.Helper()
	scriptHash := sha256.Sum256(script)
	if hex.EncodeToString(scriptHash[:]) != bundle.ScriptSHA256 || int64(len(script)) != bundle.ScriptSize {
		t.Fatal("ZIP deployment script differs from release")
	}
}

func (x servedInstallerFixture) assertServedMSI(t *testing.T, state installerModeState) {
	path, org, keyID := state.path, state.org, state.keyID
	sourceFiles, bundle, a, config := x.sourceFiles, x.bundle, x.setup.app, x.setup.config
	if hex.EncodeToString(state.digest[:]) != bundle.SHA256 {
		t.Fatal("served MSI differs from immutable release")
	}
	servedFiles := extractMSIPayloadFiles(t, path)
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
	if strings.TrimSpace(string(raw)) != "{}" {
		t.Fatal("generic MSI embeds organization data")
	}
	raw, e = os.ReadFile(filepath.Join(x.output, state.provision))
	if e != nil {
		t.Fatal(e)
	}
	var provision InstallerProvision
	if json.Unmarshal(raw, &provision) != nil || provision.Edition != Edition || provision.Platform != "windows" || provision.Version != bundle.Version || provision.ProfileID != keyID || provision.ServerURL != config.AppURL || provision.PolicyPublicKey != base64.StdEncoding.EncodeToString(a.policyKey(org).Public().(ed25519.PublicKey)) || provision.UpdatePublicKey != base64.StdEncoding.EncodeToString(config.UpdatePublicKey) || len(provision.BootstrapToken) != 43 {
		t.Fatal("served MSI provision does not match synthetic organization")
	}
}

func (x servedInstallerFixture) assertModeRetry(t *testing.T, ctx context.Context, state *installerModeState) {
	for attempt := 0; attempt < 2; attempt++ {
		x.observer.observe(t, state.msi, state.provision, Edition+"-"+state.mode+"-state", state.hostname, Edition, true)
		projectedID := x.projectedModeDeviceID(t, *state)
		x.assertStoredModeDevice(t, ctx, state, projectedID, attempt)
	}
}

func (x servedInstallerFixture) assertStoredModeDevice(t *testing.T, ctx context.Context, state *installerModeState, projectedID string, attempt int) {
	tx, err := tenantTx(ctx, x.setup.db, state.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	device := readStoredModeDevice(t, ctx, tx, projectedID)
	x.assertModeDeviceFields(t, ctx, tx, state, device, attempt)
	assertModeEnrollment(t, ctx, tx, *state, device.id)
	tx.Rollback(ctx)
}

type storedModeDevice struct {
	id, status, version, kind, alias, sealed string
	hash                                     []byte
}

func readStoredModeDevice(t *testing.T, ctx context.Context, tx pgx.Tx, projectedID string) storedModeDevice {
	var count int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM devices WHERE id=$1", projectedID).Scan(&count); err != nil || count != 1 {
		t.Fatal("bootstrap must create exactly one device in target organization", count, err)
	}
	var device storedModeDevice
	if err := tx.QueryRow(ctx, "SELECT id,credential_hash,status,version,kind,hostname,hostname_ciphertext FROM devices WHERE id=$1", projectedID).Scan(&device.id, &device.hash, &device.status, &device.version, &device.kind, &device.alias, &device.sealed); err != nil {
		t.Fatal(err)
	}
	return device
}

func (x servedInstallerFixture) assertModeDeviceFields(t *testing.T, ctx context.Context, tx pgx.Tx, state *installerModeState, device storedModeDevice, attempt int) {
	org, hostname, mode := state.org, state.hostname, state.mode
	plaintext, openErr := x.setup.app.openShadow(org, "device-name:"+device.id, device.sealed)
	if openErr != nil || string(plaintext) != hostname || device.alias != deviceAlias(device.id) || device.sealed == "" || strings.Contains(device.sealed, hostname) {
		t.Fatal("machine name must be recoverable only from its sealed storage")
	}
	var count int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM devices WHERE hostname=$1", hostname).Scan(&count); err != nil || count != 0 {
		t.Fatal("machine name stored in plaintext", err)
	}
	expectedStatus := "approved"
	if mode == "manual" {
		expectedStatus = "pending"
	}
	expectedKind := "browser"
	if Edition == "commercial" {
		expectedKind = "native"
	}
	if device.status != expectedStatus || device.version != x.bundle.Version || device.kind != expectedKind {
		t.Fatal("real bootstrap did not honor approval/version/edition", device.status, device.version, device.kind)
	}
	if attempt == 0 {
		state.deviceID, state.credentialHash = device.id, device.hash
	} else if state.deviceID != device.id || !bytes.Equal(state.credentialHash, device.hash) {
		t.Fatal("repair changed existing identity")
	}
}

func assertModeEnrollment(t *testing.T, ctx context.Context, tx pgx.Tx, state installerModeState, deviceID string) {
	var currentKey string
	var uses, count int
	if err := tx.QueryRow(ctx, "SELECT id,uses FROM installer_profiles WHERE platform IS NULL AND NOT revoked").Scan(&currentKey, &uses); err != nil || currentKey != state.keyID || uses != state.beforeUses+1 {
		t.Fatal("bootstrap rotated key or counted retry as new enrollment", err)
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM installer_installations WHERE device_id=$1", deviceID).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate enrollment", err)
	}
}

func (x servedInstallerFixture) assertManualApproval(t *testing.T, ctx context.Context, state installerModeState) {
	mode, deviceID, org, cookie, token := state.mode, state.deviceID, state.org, state.cookie, state.token
	db, caller := x.setup.db, x.caller
	if mode == "manual" {
		requireHTTP(t, caller.call(t, "POST", "/api/devices/"+deviceID+"/approve", map[string]any{}, cookie, token), 200)
		tx, e := tenantTx(ctx, db, org)
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
}

func (x servedInstallerFixture) assertChildIsolation(t *testing.T, ctx context.Context, state installerModeState) {
	index, deviceID, root, db := state.index, state.deviceID, x.setup.root, x.setup.db
	if Edition == "commercial" && index == 1 {
		tx, e := tenantTx(ctx, db, root)
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
}

func (x servedInstallerFixture) projectedModeDeviceID(t *testing.T, state installerModeState) string {
	caller, cookie, token, hostname := x.caller, state.cookie, state.token, state.hostname
	view := caller.call(t, "GET", "/api/devices", nil, cookie, token)
	requireHTTP(t, view, 200)
	var devices struct {
		Items []struct{ ID, Hostname string }
	}
	if e := json.Unmarshal(view.Body.Bytes(), &devices); e != nil {
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
	return projectedID
}
