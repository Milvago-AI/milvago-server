package app

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func firefoxXPI(t *testing.T, manifests ...string) []byte {
	t.Helper()
	var payload bytes.Buffer
	archive := zip.NewWriter(&payload)
	for _, manifest := range manifests {
		entry, err := archive.Create("manifest.json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = entry.Write([]byte(manifest)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return payload.Bytes()
}

// Firefox reads a JSON update manifest, not the Omaha XML Chrome uses. Its update
// version and identity must be obtained from the signed XPI that the route serves;
// version.txt belongs only to the Chromium CRX update manifest.
func TestFirefoxUpdateManifest(t *testing.T) {
	directory := t.TempDir()
	assets := filepath.Join(directory, "ext")
	if err := os.MkdirAll(assets, 0o755); err != nil {
		t.Fatal(err)
	}
	a := &App{config: Config{StaticDir: directory, AppURL: "https://console.example.test"}}
	serve := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		a.extFirefoxUpdate(w, httptest.NewRequest("GET", "/ext/updates.json", nil))
		return w
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(assets, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeXPI := func(payload []byte) {
		if err := os.WriteFile(filepath.Join(assets, "milvago.xpi"), payload, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if w := serve(); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("wanted 503 without a package, got %d: %s", w.Code, w.Body.String())
	}

	manifest := "{\"version\":\"0.5.10\",\"browser_specific_settings\":{\"gecko\":{\"id\":\"browser@milvago.app\"}}}"
	payload := firefoxXPI(t, manifest)
	writeXPI(payload)
	// The CRX release is newer; Firefox must still announce its signed XPI version.
	write("version.txt", "0.5.12\n")
	write("extension-firefox-id.txt", "browser@milvago.app\n")

	w := serve()
	if w.Code != http.StatusOK {
		t.Fatalf("wanted 200, got %d: %s", w.Code, w.Body.String())
	}
	var document struct {
		Addons map[string]struct {
			Updates []struct {
				Version    string "json:\"version\""
				UpdateLink string "json:\"update_link\""
				UpdateHash string "json:\"update_hash\""
			} "json:\"updates\""
		} "json:\"addons\""
	}
	if err := json.Unmarshal(w.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	entry, ok := document.Addons["browser@milvago.app"]
	if !ok || len(entry.Updates) != 1 {
		t.Fatalf("manifest is not keyed by the add-on identity: %s", w.Body.String())
	}
	digest := sha256.Sum256(payload)
	if entry.Updates[0].Version != "0.5.10" ||
		entry.Updates[0].UpdateLink != "https://console.example.test/ext/milvago.xpi" ||
		entry.Updates[0].UpdateHash != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatalf("manifest does not describe the served package: %s", w.Body.String())
	}

	write("extension-firefox-id.txt", "other@milvago.app\n")
	if w := serve(); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("wanted 503 for a mismatched identity, got %d: %s", w.Code, w.Body.String())
	}
	write("extension-firefox-id.txt", "browser@milvago.app\n")
	writeXPI(firefoxXPI(t))
	if w := serve(); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("wanted 503 without manifest.json, got %d: %s", w.Code, w.Body.String())
	}
	writeXPI(firefoxXPI(t, manifest, manifest))
	if w := serve(); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("wanted 503 for duplicate manifest.json, got %d: %s", w.Code, w.Body.String())
	}
	invalid := []struct {
		name    string
		payload []byte
	}{
		{"invalid archive", []byte("not a ZIP archive")},
		{"invalid JSON", firefoxXPI(t, "{")},
		{"invalid version", firefoxXPI(t, "{\"version\":\"invalid\",\"browser_specific_settings\":{\"gecko\":{\"id\":\"browser@milvago.app\"}}}")},
		{"trailing JSON", firefoxXPI(t, manifest+" {}")},
		{"oversized manifest", firefoxXPI(t, manifest+strings.Repeat(" ", int(firefoxManifestLimit)+1))},
	}
	for _, test := range invalid {
		writeXPI(test.payload)
		if w := serve(); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("wanted 503 for %s, got %d: %s", test.name, w.Code, w.Body.String())
		}
	}
}
