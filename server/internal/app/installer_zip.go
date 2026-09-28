package app

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
)

const windowsPackageName = "milvago-windows-package.zip"

// Only the provisioning document varies by organization. The MSI and script
// are copied from the verified release before they enter the ZIP.
func (a *App) downloadWindowsPackage(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := requireIndividual(r); err != nil {
		return err
	}
	// A session authenticated with a second factor must refresh that proof for
	// the sensitive download. Accounts without an enabled factor remain usable.
	if s.MFA {
		if err := a.requireFreshMFA(r, tx, s); err != nil {
			return err
		}
	}
	provision, err := a.installerProvision(r.Context(), tx, s.OrganizationID, "windows")
	if err != nil {
		return err
	}
	bundle, source, err := a.releaseBundle("windows")
	if err != nil {
		return err
	}
	script, err := readWindowsReleaseScript(bundle, source)
	if err != nil {
		return err
	}
	provision.Version = bundle.Version
	provision.ExpiresAt = time.Now().UTC().Add(deploymentHorizon)
	if err = audit(r.Context(), tx, s.OrganizationID, s.UserID, "deployment_key.download", provision.ProfileID); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	if !installerStreams.acquire("person "+s.UserID, 2) {
		return apiError{429, "installer_busy", msgInstallerBusy}
	}
	defer installerStreams.release("person " + s.UserID)
	if !installerStreams.acquire("", 8) {
		return apiError{429, "installer_busy", msgInstallerBusy}
	}
	defer installerStreams.release("")
	select {
	case installerBuildSlots <- struct{}{}:
	default:
		return apiError{429, "installer_busy", msgInstallerBusy}
	}
	building := true
	endBuild := func() {
		if building {
			building = false
			<-installerBuildSlots
		}
	}
	defer endBuild()
	directory, err := os.MkdirTemp("", "milvago-windows-package-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	copyPath := filepath.Join(directory, "installer.msi")
	size, digest, err := copyInstallerFileAndHash(source, copyPath, installerBundleLimit)
	if err != nil {
		return err
	}
	if size != bundle.Size || digest != bundle.SHA256 {
		return apiError{503, "installer_changed", "The release changed during preparation. Try again."}
	}
	provisionJSON, err := json.Marshal(provision)
	if err != nil {
		return err
	}
	archivePath := filepath.Join(directory, windowsPackageName)
	archive, err := createConfined(archivePath, 0600)
	if err != nil {
		return err
	}
	writer := zip.NewWriter(archive)
	for _, item := range []struct {
		name string
		body []byte
		path string
	}{
		{name: "milvago-windows-installer.msi", path: copyPath},
		{name: "milvago-windows-install.ps1", body: script},
		{name: "milvago-provision.json", body: provisionJSON},
	} {
		var input io.Reader = bytes.NewReader(item.body)
		if item.path != "" {
			file, openErr := openConfined(item.path)
			if openErr != nil {
				writer.Close()
				archive.Close()
				return openErr
			}
			defer file.Close()
			input = file
		}
		entry, createErr := writer.CreateHeader(&zip.FileHeader{Name: item.name, Method: zip.Store})
		if createErr == nil {
			_, createErr = io.Copy(entry, input)
		}
		if createErr != nil {
			writer.Close()
			archive.Close()
			return createErr
		}
	}
	if err = writer.Close(); err != nil {
		archive.Close()
		return err
	}
	if err = archive.Close(); err != nil {
		return err
	}
	file, err := openConfined(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128*1024*1024+1024*1024 {
		return errors.New("invalid Windows installer package")
	}
	endBuild()
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Milvago-Installer-Version", bundle.Version)
	w.Header().Set("Content-Disposition", `attachment; filename="`+windowsPackageName+`"`)
	http.ServeContent(w, r, windowsPackageName, info.ModTime(), file)
	return nil
}
