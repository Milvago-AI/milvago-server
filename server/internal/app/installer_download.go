package app

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var installerBuildSlots = make(chan struct{}, 2)

// installerStreams counts the downloads in flight, per person and in all ("").
var installerStreams = &orgSlots{held: map[string]int{}}

type orgSlots struct {
	sync.Mutex
	held map[string]int
}

func (o *orgSlots) acquire(org string, limit int) bool {
	o.Lock()
	defer o.Unlock()
	if o.held[org] >= limit {
		return false
	}
	o.held[org]++
	return true
}

func (o *orgSlots) release(org string) {
	o.Lock()
	defer o.Unlock()
	if o.held[org]--; o.held[org] <= 0 {
		delete(o.held, org)
	}
}

const fileProvisionJSON = "provision.json"

func (a *App) downloadInstaller(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	provision, err := a.installerProvision(r.Context(), tx, s.OrganizationID, r.PathValue("platform"))
	if err != nil {
		return err
	}
	bundle, source, err := a.releaseBundle(provision.Platform)
	if err != nil {
		return err
	}
	// The version is the one the current release carries, not one frozen when a
	// package was created: a durable key must never go stale against a new release.
	provision.Version = bundle.Version
	provision.ExpiresAt = time.Now().UTC().Add(deploymentHorizon)
	// The download is recorded before the lock is released, in the transaction that
	// read the key: it records that a download was authorised, which is the fact
	// worth keeping even if the packaging then fails.
	if err = audit(r.Context(), tx, s.OrganizationID, s.UserID, "deployment_key.download", provision.ProfileID); err != nil {
		return err
	}
	// Release the key's row lock before building. `installerProvision` reads it FOR
	// SHARE, and the build below repackages a release of up to a hundred megabytes:
	// holding that lock across it would stall an emergency revocation for as long
	// as a download takes. A rotation that commits while this build runs
	// simply produces one stale installer, which is what rotation is for.
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	// Two downloads in flight per person (a key counts as its creator), whatever their
	// speed -- per organization, an owner multiplied them through child organizations.
	// The two global build slots are held for the build only. Held until the transfer ended, as they
	// were, a slow reader in one tenant kept every other tenant at 429 for as long as
	// the write timeout (audit of 2026-09-24).
	// And eight in all: each transfer keeps its built installer on disk until it ends.
	if !installerStreams.acquire("person "+s.UserID, 2) {
		return apiError{429, "installer_busy", "Installer preparation is busy. Try again shortly."}
	}
	defer installerStreams.release("person " + s.UserID)
	if !installerStreams.acquire("", 8) {
		return apiError{429, "installer_busy", "Installer preparation is busy. Try again shortly."}
	}
	defer installerStreams.release("")
	select {
	case installerBuildSlots <- struct{}{}:
	default:
		return apiError{429, "installer_busy", "Installer preparation is busy. Try again shortly."}
	}
	building := true
	endBuild := func() {
		if building {
			building = false
			<-installerBuildSlots
		}
	}
	defer endBuild()
	directory, err := os.MkdirTemp("", "milvago-installer-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	// Build only from the verified private snapshot, including during release rotation.
	snapshot := filepath.Join(directory, "source"+filepath.Ext(source))
	size, digest, err := copyInstallerFileAndHash(source, snapshot, installerBundleLimit)
	if err != nil {
		return err
	}
	if size != bundle.Size || digest != bundle.SHA256 {
		return apiError{503, "installer_changed", "The release changed during preparation. Try again."}
	}
	source = snapshot
	raw, err := json.Marshal(provision)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(directory, fileProvisionJSON), raw, 0600); err != nil {
		return err
	}
	var result string
	if provision.Platform == "windows" {
		result = filepath.Join(directory, "milvago.msi")
		err = setMSIBinaryStream(source, result, "MilvagoProvision", raw)
	} else {
		result, err = buildInstallerRPM(directory, source, provision)
	}
	if err != nil {
		return apiError{503, "installer_build_failed", "The installer could not be prepared. Verify the server package builder configuration."}
	}
	file, err := openConfined(result)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 128*1024*1024 {
		return fmt.Errorf("invalid generated installer")
	}
	endBuild()
	// The release snapshot is the largest file here and is not served.
	_ = os.Remove(source)
	extension := "msi"
	media := "application/x-msi"
	if provision.Platform == "linux" {
		extension = "rpm"
		media = "application/x-rpm"
	}
	name := fmt.Sprintf("milvago-%s-%s-%s.%s", Edition, provision.Version, provision.ProfileID[:8], extension)
	w.Header().Set("Content-Type", media)
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// This value is read by the console only after it has received this verified release.
	w.Header().Set("X-Milvago-Installer-Version", bundle.Version)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeContent(w, r, name, info.ModTime(), file)
	return nil
}
// The installer files live in the release directory or in this request's own temporary
// directory. They are opened through an os.Root on their parent, so the last component
// can never resolve through a link out of it.
func openConfined(path string) (*os.File, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.Open(filepath.Base(path))
}

func createConfined(path string, mode os.FileMode) (*os.File, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.OpenFile(filepath.Base(path), os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
}

func readConfined(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(filepath.Base(path))
}

func copyInstallerFile(source, target string) error {
	_, _, err := copyInstallerFileAndHash(source, target, installerBundleLimit)
	return err
}

func copyInstallerFileAndHash(source, target string, limit int64) (int64, string, error) {
	input, err := openConfined(source)
	if err != nil {
		return 0, "", err
	}
	defer input.Close()
	output, err := createConfined(target, 0600)
	if err != nil {
		return 0, "", err
	}
	digest := sha256.New()
	n, err := io.Copy(io.MultiWriter(output, digest), io.LimitReader(input, limit+1))
	if err != nil {
		_ = output.Close()
		return 0, "", err
	}
	if n > limit {
		_ = output.Close()
		return 0, "", fmt.Errorf("file too large")
	}
	if err = output.Close(); err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(digest.Sum(nil)), nil
}
func extractInstallerPayload(source, target string) error {
	file, err := openConfined(source)
	if err != nil {
		return err
	}
	defer file.Close()
	// Everything is written through an os.Root on the target: on top of the name checks
	// below, no entry can land outside it.
	destination, err := os.OpenRoot(target)
	if err != nil {
		return err
	}
	defer destination.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer reader.Close()
	archive := tar.NewReader(reader)
	var total int64
	count := 0
	for {
		header, err := archive.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		count++
		name := strings.TrimPrefix(header.Name, "./")
		if name == "" && header.Typeflag == tar.TypeDir {
			continue
		}
		clean := filepath.Clean(name)
		if count > 1000 || name == "" || strings.HasPrefix(name, "/") || filepath.IsAbs(name) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || strings.ContainsAny(name, "\\:\x00") {
			return fmt.Errorf("unsafe installer payload")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err = destination.MkdirAll(clean, 0700); err != nil {
				return err
			}
		case tar.TypeReg:
			total += header.Size
			if header.Size < 0 || total > installerBundleLimit {
				return fmt.Errorf("installer payload exceeds limit")
			}
			if err = destination.MkdirAll(filepath.Dir(clean), 0700); err != nil {
				return err
			}
			mode := os.FileMode(0644)
			if header.Mode&0111 != 0 {
				mode = 0755
			}
			output, err := destination.OpenFile(clean, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			_, err = io.CopyN(output, archive, header.Size)
			closeErr := output.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return fmt.Errorf("installer links and special files are forbidden")
		}
	}
}
func validateInstallerPayload(payload, edition string) error {
	agent := "milvago-browser-agent"
	if edition == "commercial" {
		agent = "milvago-commercial-bridge"
	}
	executables := []string{agent, "milvago-updater"}
	if edition == "commercial" {
		executables = append(executables, "milvago-model-filter", "milvago-collector")
	}
	for _, name := range executables {
		path := filepath.Join(payload, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
			return fmt.Errorf("invalid installer executable: %s", name)
		}
		file, err := openConfined(path)
		if err != nil {
			return err
		}
		header := make([]byte, 20)
		_, err = io.ReadFull(file, header)
		closeErr := file.Close()
		if err != nil || closeErr != nil || string(header[:4]) != "\x7fELF" || header[4] != 2 || header[5] != 1 || header[18] != 0x3e || header[19] != 0 {
			return fmt.Errorf("installer executable is not x86_64 ELF: %s", name)
		}
	}
	filterFiles := []string{"milvago-collector", "milvago-model-filter", "register-model-filter.sh", "selinux/milvago_filter.te", "selinux/milvago_filter.fc"}
	for _, name := range filterFiles {
		info, err := os.Lstat(filepath.Join(payload, filepath.FromSlash(name)))
		if edition == "community" {
			if err == nil || !os.IsNotExist(err) {
				return fmt.Errorf("Enterprise filter in Community payload")
			}
		} else if err != nil || !info.Mode().IsRegular() || (strings.HasSuffix(name, ".sh") && info.Mode()&0111 == 0) {
			return fmt.Errorf("invalid model filter payload")
		}
	}
	session := filepath.Join(payload, "agent-session.sh")
	info, err := os.Lstat(session)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return fmt.Errorf("invalid installer session script")
	}
	extensionID := filepath.Join(payload, "extension-id.txt")
	info, err = os.Lstat(extensionID)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("invalid installer extension identity")
	}
	id, err := readConfined(extensionID)
	if err != nil || len(strings.TrimSpace(string(id))) != 32 {
		return fmt.Errorf("invalid installer extension identity")
	}
	for _, c := range strings.TrimSpace(string(id)) {
		if c < 'a' || c > 'p' {
			return fmt.Errorf("invalid installer extension identity")
		}
	}
	return nil
}
