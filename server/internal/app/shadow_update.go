package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

type UpdateManifest struct {
	Format       string    `json:"format,omitempty"`
	Version      string    `json:"version"`
	Edition      string    `json:"edition"`
	Platform     string    `json:"platform"`
	Protocol     int       `json:"protocol"`
	SHA256       string    `json:"sha256"`
	Size         int64     `json:"size"`
	ExpiresAt    time.Time `json:"expires_at"`
	Artifact     string    `json:"artifact"`
	RollbackFrom []string  `json:"rollback_from"`
}
type signedEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

const (
	msgReleaseArtifactUnverified = "The release artifact could not be verified."
)

// Updates are served from the very installers the console hands out: one artifact,
// one directory. A signed manifest sits next to each installer and is what actually
// authorizes an update; the trust anchor is the separate release key.
func (a *App) updatesAvailable() bool {
	directory := os.Getenv("MILVAGO_INSTALLER_DIRECTORY")
	if len(a.config.UpdatePublicKey) != 32 || directory == "" {
		return false
	}
	info, e := os.Stat(directory)
	return e == nil && info.IsDir()
}
func versionNewer(v, current string) bool {
	if !versionPattern.MatchString(current) {
		return true
	}
	x, y := strings.Split(v, "."), strings.Split(current, ".")
	for i := range x {
		a, _ := strconv.Atoi(x[i])
		b, _ := strconv.Atoi(y[i])
		if a != b {
			return a > b
		}
	}
	return false
}
func (a *App) readUpdateManifest(edition, platform string) (signedEnvelope, UpdateManifest, error) {
	var env signedEnvelope
	var m UpdateManifest
	if !a.updatesAvailable() {
		return env, m, os.ErrNotExist
	}
	if !slices.Contains([]string{"community", "commercial"}, edition) || !slices.Contains([]string{"windows", "linux"}, platform) {
		return env, m, os.ErrNotExist
	}
	path := filepath.Join(os.Getenv("MILVAGO_INSTALLER_DIRECTORY"), edition+"-"+platform+"-update.json")
	info, e := os.Lstat(path)
	if e != nil {
		return env, m, e
	}
	if !info.Mode().IsRegular() || info.Size() > 65536 {
		return env, m, errors.New("invalid release manifest file")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return env, m, e
	}
	if json.Unmarshal(raw, &env) != nil {
		return env, m, errors.New("invalid release envelope")
	}
	payload, e := base64.StdEncoding.DecodeString(env.Payload)
	if e != nil {
		return env, m, e
	}
	signature, e := base64.StdEncoding.DecodeString(env.Signature)
	if e != nil || !ed25519.Verify(a.config.UpdatePublicKey, payload, signature) {
		return env, m, errors.New("release signature verification failed")
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if e = d.Decode(&m); e != nil {
		return env, m, e
	}
	if d.Decode(new(any)) != io.EOF {
		return env, m, errors.New("trailing release manifest data")
	}
	if m.Format == "" {
		m.Format = "binary"
	}
	if !slices.Contains([]string{"binary", "msi"}, m.Format) || (m.Format == "msi" && m.Platform != "windows") || m.Edition != edition || m.Platform != platform || m.Protocol != 2 || !versionPattern.MatchString(m.Version) || !digestPattern.MatchString(m.SHA256) || m.Size < 1 || m.Size > 128*1024*1024 || !m.ExpiresAt.After(time.Now()) || m.Artifact != "/v2/update/artifact/"+m.SHA256 || len(m.RollbackFrom) > 50 {
		return env, m, errors.New("release manifest constraints failed")
	}
	for _, v := range m.RollbackFrom {
		if !versionPattern.MatchString(v) {
			return env, m, errors.New("invalid authorized rollback")
		}
	}
	return env, m, nil
}

// releaseArtifactReady reports whether the signed manifest actually corresponds to an
// installer this server can deliver. A manifest is only half the release: without
// this, a correctly signed manifest whose artifact is missing or has been replaced
// would still be announced, and every device would keep asking for bytes that can
// never be served.
func (a *App) releaseArtifactReady(m UpdateManifest) bool {
	bundle, _, e := a.releaseBundle(m.Platform)
	return e == nil && bundle.SHA256 == m.SHA256 && bundle.Size == m.Size
}

func (a *App) applicableUpdate(r *http.Request, tx pgx.Tx, org, device string) (signedEnvelope, UpdateManifest, bool, error) {
	var env signedEnvelope
	var m UpdateManifest
	cfg, e := a.effectiveShadow(r.Context(), tx, org, device)
	if e != nil {
		return env, m, false, e
	}
	u := cfg.Config.Operations.Updates
	if !a.updatesAvailable() || !u.Enabled {
		return env, m, false, nil
	}
	if len(u.DeviceIDs) > 0 && !slices.Contains(u.DeviceIDs, device) {
		return env, m, false, nil
	}
	digest := sha256.Sum256([]byte(device))
	if int(binary.BigEndian.Uint64(digest[:8])%100) >= u.Percentage {
		return env, m, false, nil
	}
	var kind, platform, current string
	if e = tx.QueryRow(r.Context(), `SELECT kind,platform,version FROM devices WHERE id=$1`, device).Scan(&kind, &platform, &current); e != nil {
		return env, m, false, e
	}
	edition := "community"
	if kind == "native" {
		if Edition != "commercial" {
			return env, m, false, forbidden()
		}
		edition = "commercial"
	}
	platform = strings.ToLower(platform)
	if strings.HasPrefix(platform, "windows") {
		platform = "windows"
	}
	if strings.HasPrefix(platform, "linux") {
		platform = "linux"
	}
	env, m, e = a.readUpdateManifest(edition, platform)
	if errors.Is(e, os.ErrNotExist) {
		return env, m, false, nil
	}
	if e != nil {
		return env, m, false, apiError{503, "release_invalid", "The published release could not be verified."}
	}
	if slices.Contains(u.PausedVersions, m.Version) || (!versionNewer(m.Version, current) && !slices.Contains(m.RollbackFrom, current)) {
		return env, m, false, nil
	}
	// Never offer a release whose artifact this server cannot actually deliver.
	if !a.releaseArtifactReady(m) {
		return env, m, false, nil
	}
	return env, m, true, nil
}
func (a *App) updateManifest(w http.ResponseWriter, r *http.Request) {
	tx, org, device, e := a.deviceTx(r)
	if e != nil {
		a.fail(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	env, _, offered, e := a.applicableUpdate(r, tx, org, device)
	if e != nil {
		a.fail(w, e)
		return
	}
	if !offered {
		w.WriteHeader(204)
		return
	}
	reply(w, 200, env)
}

// updateAnchor publishes the successor release trust anchor, when the operator has
// prepared one. The document is signed offline with the *current* release key — the
// server never holds it — so a compromised server cannot rotate the anchor. Devices
// verify it against the anchor pinned at enrolment before storing the successor.
func (a *App) updateAnchor(w http.ResponseWriter, r *http.Request) {
	tx, _, _, e := a.deviceTx(r)
	if e != nil {
		a.fail(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	if !a.updatesAvailable() {
		w.WriteHeader(204)
		return
	}
	raw, err := os.ReadFile(filepath.Join(os.Getenv("MILVAGO_INSTALLER_DIRECTORY"), "anchor.json"))
	if err != nil || len(raw) > 8192 {
		w.WriteHeader(204)
		return
	}
	var envelope signedEnvelope
	if json.Unmarshal(raw, &envelope) != nil {
		w.WriteHeader(204)
		return
	}
	payload, e1 := base64.StdEncoding.DecodeString(envelope.Payload)
	signature, e2 := base64.StdEncoding.DecodeString(envelope.Signature)
	if e1 != nil || e2 != nil || !ed25519.Verify(a.config.UpdatePublicKey, payload, signature) {
		w.WriteHeader(204)
		return
	}
	reply(w, 200, envelope)
}

var artifactSlots = make(chan struct{}, 2)

// artifactHolders keeps one download slot per device: one device within its budget
// held both global slots and every other device got 503 (audit of 2026-09-24).
var artifactHolders sync.Map

func (a *App) updateArtifact(w http.ResponseWriter, r *http.Request) {
	tx, org, device, e := a.deviceTx(r)
	if e != nil {
		a.fail(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	_, m, offered, e := a.applicableUpdate(r, tx, org, device)
	if e != nil {
		a.fail(w, e)
		return
	}
	if !offered || r.PathValue("sha256") != m.SHA256 {
		a.fail(w, apiError{404, "not_found", "No matching authorized release."})
		return
	}
	if _, busy := artifactHolders.LoadOrStore(device, struct{}{}); busy {
		a.fail(w, apiError{503, "download_busy", "Try the release download again shortly."})
		return
	}
	defer artifactHolders.Delete(device)
	select {
	case artifactSlots <- struct{}{}:
		defer func() { <-artifactSlots }()
	default:
		a.fail(w, apiError{503, "download_busy", "Try the release download again shortly."})
		return
	}
	// The signed manifest authorizes; the install manifest only locates the file the
	// console already serves. Its name is therefore untrusted: the bytes are hashed
	// against the signed digest before anything leaves the server.
	bundle, path, e := a.releaseBundle(m.Platform)
	if e != nil || bundle.SHA256 != m.SHA256 || bundle.Size != m.Size {
		a.fail(w, apiError{503, "artifact_invalid", msgReleaseArtifactUnverified})
		return
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() != m.Size {
		a.fail(w, apiError{503, "artifact_invalid", msgReleaseArtifactUnverified})
		return
	}
	// Committed before the copy: the transaction holds the device row FOR UPDATE and a
	// pool connection, which a copy and re-hash of up to 128 MB kept for its whole
	// duration, stalling a revocation of that device (audit of 2026-09-24).
	if e = audit(r.Context(), tx, org, "device:"+device, "update.download", m.Version); e != nil {
		a.fail(w, e)
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		a.fail(w, e)
		return
	}
	directory, e := os.MkdirTemp("", "milvago-update-")
	if e != nil {
		a.fail(w, apiError{503, "artifact_invalid", msgReleaseArtifactUnverified})
		return
	}
	defer os.RemoveAll(directory)
	snapshot := filepath.Join(directory, "artifact")
	size, digest, e := copyInstallerFileAndHash(path, snapshot, m.Size)
	if e != nil || size != m.Size || digest != m.SHA256 {
		a.fail(w, apiError{503, "artifact_invalid", msgReleaseArtifactUnverified})
		return
	}
	verified, e := os.Open(snapshot)
	if e != nil {
		a.fail(w, apiError{503, "artifact_invalid", msgReleaseArtifactUnverified})
		return
	}
	defer verified.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "milvago-update.bin", time.Time{}, verified)
}
func (a *App) updateStatus(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Version string `json:"version"`
		Status  string `json:"status"`
	}
	if e := decode(w, r, &body); e != nil {
		a.fail(w, e)
		return
	}
	if !versionPattern.MatchString(body.Version) || !slices.Contains([]string{"installed", "rolled_back", "failed", "reboot_required"}, body.Status) {
		a.fail(w, bad("Invalid update status."))
		return
	}
	tx, org, device, e := a.deviceTx(r)
	if e != nil {
		a.fail(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	// Audited only when the report changes something: the audit log is append-only,
	// and a device repeating the same status at its budget wrote tens of thousands of
	// rows a day that no purge could remove (audit of 2026-09-24).
	var changed bool
	e = tx.QueryRow(r.Context(), `WITH prior AS (SELECT version,update_status FROM devices WHERE id=$3)
UPDATE devices d SET version=CASE WHEN $1 IN ('failed','reboot_required') THEN d.version ELSE $2 END,update_status=$1,update_reported_at=now() FROM prior WHERE d.id=$3
RETURNING prior.version IS DISTINCT FROM d.version OR prior.update_status IS DISTINCT FROM d.update_status`, body.Status, body.Version, device).Scan(&changed)
	// And at most six an hour per device: alternating two versions made every report
	// a change.
	if e == nil && changed {
		var recent int
		if e = tx.QueryRow(r.Context(), `SELECT count(*) FROM audit WHERE organization_id=$1 AND actor=$2 AND action='update.report' AND occurred_at>now()-interval '1 hour'`, org, "device:"+device).Scan(&recent); e == nil && recent < 6 {
			e = audit(r.Context(), tx, org, "device:"+device, "update.report", fmt.Sprintf("%s:%s", body.Version, body.Status))
		}
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		a.fail(w, e)
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
