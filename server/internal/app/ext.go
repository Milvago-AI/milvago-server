package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// publicOrigin returns the agent-facing HTTPS origin advertised to devices
// (enrollment server_url, installer ServerURL, extension update.xml codebase).
// Source of truth is the instance-level app_config.public_url setting, editable
// in Administration; it falls back to the immutable APP_URL env origin when the
// setting is empty or (defensively) not a valid bare origin. This value is
// deliberately distinct from APP_URL, which stays bound to OIDC/CSRF/cookies.
// rowQuerier is a pool or an open transaction. A handler holding its request
// transaction reads through it: taking a second pool connection while holding the
// first let ten concurrent requests exhaust a ten-connection pool and stall every
// database user of the pod (audit of 2026-09-24).
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func (a *App) publicOrigin(ctx context.Context) string {
	// No pool means no instance configuration to read: the configured application URL
	// is the answer, not a panic.
	if a.db == nil {
		return a.config.AppURL
	}
	return a.publicOriginIn(ctx, a.db)
}

func (a *App) publicOriginIn(ctx context.Context, q rowQuerier) string {
	var stored string
	if e := q.QueryRow(ctx, `SELECT public_url FROM app_config`).Scan(&stored); e != nil {
		return a.config.AppURL
	}
	stored = strings.TrimRight(strings.TrimSpace(stored), "/")
	if stored == "" || !validOrigin(stored) {
		return a.config.AppURL
	}
	return stored
}

var extVersionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,3}$`)

// Gecko add-on identities are e-mail-shaped or a GUID; only the shape this product
// uses is accepted, so a corrupted asset cannot inject anything into the manifest.
var geckoIDPattern = regexp.MustCompile(`^[a-z0-9._-]+@[a-z0-9.-]+$`)
var extIDPattern = regexp.MustCompile(`^[a-p]{32}$`)

const firefoxManifestLimit int64 = 64 * 1024

const (
	fileMilvagoCRX                  = "milvago.crx"
	fileMilvagoXPI                  = "milvago.xpi"
	msgExtensionHostingUnconfigured = "Extension hosting is not configured on this instance."
	headerContentType               = "Content-Type"
	headerXContentTypeOptions       = "X-Content-Type-Options"
)

type firefoxXPIMetadata struct {
	Version                 string `json:"version"`
	BrowserSpecificSettings struct {
		Gecko struct {
			ID string `json:"id"`
		} `json:"gecko"`
	} `json:"browser_specific_settings"`
}

// firefoxXPIInfo binds an update manifest to the signed XPI that the route will
// serve. The archive may contain only one bounded manifest.json; a sidecar version
// could otherwise announce a CRX release for an older Firefox package.
func firefoxXPIInfo(payload []byte) (string, string, error) {
	archive, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return "", "", fmt.Errorf("invalid Firefox package: %w", err)
	}
	var manifest *zip.File
	for _, entry := range archive.File {
		if entry.Name != "manifest.json" {
			continue
		}
		if manifest != nil {
			return "", "", fmt.Errorf("duplicate Firefox manifest")
		}
		manifest = entry
	}
	if manifest == nil || manifest.FileInfo().IsDir() || manifest.UncompressedSize64 > uint64(firefoxManifestLimit) {
		return "", "", fmt.Errorf("invalid Firefox manifest")
	}
	file, err := manifest.Open()
	if err != nil {
		return "", "", fmt.Errorf("cannot open Firefox manifest: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, firefoxManifestLimit+1))
	if err != nil || int64(len(raw)) > firefoxManifestLimit {
		return "", "", fmt.Errorf("invalid Firefox manifest")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var metadata firefoxXPIMetadata
	if decoder.Decode(&metadata) != nil || decoder.Decode(&struct{}{}) != io.EOF || !extVersionPattern.MatchString(metadata.Version) || !geckoIDPattern.MatchString(metadata.BrowserSpecificSettings.Gecko.ID) {
		return "", "", fmt.Errorf("invalid Firefox manifest metadata")
	}
	return metadata.Version, metadata.BrowserSpecificSettings.Gecko.ID, nil
}

// extAsset resolves a file inside the baked StaticDir/ext directory. The name is
// a fixed literal at every call site (no user input), so there is no traversal
// surface; filepath.Join with a constant keeps it explicit.
func (a *App) extAsset(name string) string {
	return filepath.Join(a.config.StaticDir, "ext", name)
}

// extUpdate serves the Omaha (gupdate) manifest used by Chrome/Edge
// ExtensionInstallForcelist. It is unauthenticated (browsers fetch it
// anonymously) and exposes only the CRX version and codebase URL. The codebase
// origin comes from publicOrigin; all attribute values are emitted through
// encoding/xml, which escapes them, so a crafted public_url cannot break out of
// the XML. Returns 503 until a signed CRX has been baked into the image.
func (a *App) extUpdate(w http.ResponseWriter, r *http.Request) {
	if _, e := os.Stat(a.extAsset(fileMilvagoCRX)); e != nil {
		reply(w, 503, map[string]string{"error": "extension_unconfigured", "message": msgExtensionHostingUnconfigured})
		return
	}
	raw, e := os.ReadFile(a.extAsset("version.txt"))
	if e != nil {
		reply(w, 503, map[string]string{"error": "extension_unconfigured", "message": msgExtensionHostingUnconfigured})
		return
	}
	version := strings.TrimSpace(string(raw))
	if !extVersionPattern.MatchString(version) {
		reply(w, 503, map[string]string{"error": "extension_unconfigured", "message": msgExtensionHostingUnconfigured})
		return
	}
	// No default identity: the packages are edition-specific, so falling back to a
	// hard-coded ID would let one edition advertise the other's extension.
	idRaw, e := os.ReadFile(a.extAsset("extension-id.txt"))
	appID := strings.TrimSpace(string(idRaw))
	if e != nil || !extIDPattern.MatchString(appID) {
		reply(w, 503, map[string]string{"error": "extension_unconfigured", "message": "No packaged extension identity is available."})
		return
	}
	body, e := updateManifestXML(a.publicOrigin(r.Context()), version, appID)
	if e != nil {
		reply(w, 500, map[string]string{"error": "internal", "message": "Manifest generation failed."})
		return
	}
	w.Header().Set(headerContentType, "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(headerXContentTypeOptions, "nosniff")
	w.WriteHeader(200)
	_, _ = w.Write(body)
}

// updateManifestXML builds the Omaha gupdate document. All attribute values are
// emitted through encoding/xml, which escapes them, so an attacker-controlled
// origin cannot inject markup. Returned bytes include the XML declaration.
func updateManifestXML(origin, version, appID string) ([]byte, error) {
	type updatecheck struct {
		XMLName  xml.Name `xml:"updatecheck"`
		Codebase string   `xml:"codebase,attr"`
		Version  string   `xml:"version,attr"`
	}
	type appElement struct {
		XMLName xml.Name    `xml:"app"`
		AppID   string      `xml:"appid,attr"`
		Update  updatecheck `xml:"updatecheck"`
	}
	type gupdate struct {
		XMLName  xml.Name   `xml:"gupdate"`
		Xmlns    string     `xml:"xmlns,attr"`
		Protocol string     `xml:"protocol,attr"`
		App      appElement `xml:"app"`
	}
	doc := gupdate{
		Xmlns:    "http://www.google.com/update2/response",
		Protocol: "2.0",
		App: appElement{
			AppID:  appID,
			Update: updatecheck{Codebase: origin + "/ext/milvago.crx", Version: version},
		},
	}
	body, e := xml.Marshal(doc)
	if e != nil {
		return nil, e
	}
	return append([]byte(xml.Header), body...), nil
}

// extCRX serves the signed, baked CRX3 package with an explicit content type.
// Fixed filename, no user-controlled path. 404 when no CRX is present.
func (a *App) extCRX(w http.ResponseWriter, r *http.Request) {
	file, e := os.Open(a.extAsset(fileMilvagoCRX))
	if e != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, e := file.Stat()
	if e != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set(headerContentType, "application/x-chrome-extension")
	w.Header().Set(headerXContentTypeOptions, "nosniff")
	http.ServeContent(w, r, fileMilvagoCRX, info.ModTime(), file)
}

// extFirefoxCacheEntry memoizes the expensive part of the Firefox update
// document — reading, parsing and hashing the signed XPI — keyed on the file's
// (size, mtime). The identity sidecar is small and re-read on every request, so
// the package-identity check always reflects its current content, and the
// document itself is rebuilt per request so the advertised origin always
// follows the current public_url setting.
type extFirefoxCacheEntry struct {
	ok        bool
	size      int64
	mtime     time.Time
	version   string
	packageID string
	digest    string
}

// Firefox self-distribution.
//
// Mozilla requires an extension to be signed before Firefox Release or Beta will
// install it, whatever the enterprise policy says, so these routes stay inert until a
// signed XPI is baked into the image — exactly like the CRX. What they avoid is the
// Chrome problem: Firefox's own ExtensionSettings policy carries an `update_url`
// field, so the update origin never has to be baked into the package.
//
// `update_hash` is included deliberately. Firefox accepts an `update_link` over plain
// HTTP only when the manifest also pins the package digest, and a self-hosted
// instance is not always reachable over HTTPS.
func (a *App) extFirefoxUpdate(w http.ResponseWriter, r *http.Request) {
	unconfigured := func() {
		reply(w, 503, map[string]string{"error": "extension_unconfigured", "message": "Firefox extension hosting is not configured on this instance."})
	}
	info, e := os.Lstat(a.extAsset(fileMilvagoXPI))
	if e != nil || !info.Mode().IsRegular() {
		unconfigured()
		return
	}
	a.extFirefoxMu.Lock()
	cached := a.extFirefox
	a.extFirefoxMu.Unlock()
	if !cached.ok || cached.size != info.Size() || !cached.mtime.Equal(info.ModTime()) {
		payload, e := os.ReadFile(a.extAsset(fileMilvagoXPI))
		if e != nil {
			unconfigured()
			return
		}
		version, packageID, e := firefoxXPIInfo(payload)
		if e != nil {
			unconfigured()
			return
		}
		digest := sha256.Sum256(payload)
		cached = extFirefoxCacheEntry{ok: true, size: info.Size(), mtime: info.ModTime(), version: version, packageID: packageID, digest: hex.EncodeToString(digest[:])}
		a.extFirefoxMu.Lock()
		a.extFirefox = cached
		a.extFirefoxMu.Unlock()
	}
	rawID, e := os.ReadFile(a.extAsset("extension-firefox-id.txt"))
	if e != nil {
		unconfigured()
		return
	}
	id := strings.TrimSpace(string(rawID))
	if !geckoIDPattern.MatchString(id) || cached.packageID != id {
		unconfigured()
		return
	}
	document := map[string]any{"addons": map[string]any{id: map[string]any{"updates": []map[string]string{{
		"version":     cached.version,
		"update_link": a.publicOrigin(r.Context()) + "/ext/milvago.xpi",
		"update_hash": "sha256:" + cached.digest,
	}}}}}
	w.Header().Set(headerContentType, "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set(headerXContentTypeOptions, "nosniff")
	reply(w, 200, document)
}

// extXPI serves the signed, baked Firefox package. Fixed filename, no user-controlled
// path. 404 when none is present.
func (a *App) extXPI(w http.ResponseWriter, r *http.Request) {
	file, e := os.Open(a.extAsset(fileMilvagoXPI))
	if e != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, e := file.Stat()
	if e != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set(headerContentType, "application/x-xpinstall")
	w.Header().Set(headerXContentTypeOptions, "nosniff")
	http.ServeContent(w, r, fileMilvagoXPI, info.ModTime(), file)
}
