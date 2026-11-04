package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func linuxUpdateArtifactFixture(t *testing.T) (*App, string, UpdateManifest, []byte) {
	t.Helper()
	directory := t.TempDir()
	t.Setenv("MILVAGO_INSTALLER_DIRECTORY", directory)
	archive := []byte("synthetic initial Linux TAR archive")
	archiveHash := sha256.Sum256(archive)
	archiveName := "milvago-community-0.7.44-linux.tar.gz"
	if err := os.WriteFile(filepath.Join(directory, archiveName), archive, 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(InstallerBundle{Version: "0.7.44", Artifact: archiveName, SHA256: hex.EncodeToString(archiveHash[:]), Size: int64(len(archive))})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, Edition+"-linux.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	executable := []byte("synthetic raw executable bytes; not a distributable binary")
	executableHash := sha256.Sum256(executable)
	m := UpdateManifest{Edition: "community", Platform: "linux", Version: "0.7.44", Format: "binary", SHA256: hex.EncodeToString(executableHash[:]), Size: int64(len(executable))}
	if err = os.WriteFile(filepath.Join(directory, "milvago-community-0.7.44-linux"), executable, 0600); err != nil {
		t.Fatal(err)
	}
	return &App{}, directory, m, executable
}

func TestLinuxUpdatesUseSeparateExecutable(t *testing.T) {
	a, directory, manifest, executable := linuxUpdateArtifactFixture(t)
	install, installPath, err := a.releaseBundle("linux")
	if err != nil {
		t.Fatal(err)
	}
	update, updatePath, err := a.releaseUpdateBundle(manifest)
	if err != nil || updatePath != filepath.Join(directory, "milvago-community-0.7.44-linux") || update.SHA256 != manifest.SHA256 || update.Size != manifest.Size {
		t.Fatal("raw signed update unavailable", err)
	}
	if installPath == updatePath || install.SHA256 == update.SHA256 || !strings.HasSuffix(installPath, ".tar.gz") {
		t.Fatal("initial TAR and executable update were conflated")
	}
	actual, err := os.ReadFile(updatePath)
	if err != nil || !bytes.Equal(actual, executable) || !a.releaseArtifactReady(manifest) {
		t.Fatal("update offer did not select exact raw bytes", err)
	}
	if err = os.Remove(updatePath); err != nil {
		t.Fatal(err)
	}
	if a.releaseArtifactReady(manifest) {
		t.Fatal("missing executable fell back to installation TAR")
	}
	if _, _, err = a.releaseBundle("linux"); err != nil {
		t.Fatal("missing update removed initial installer", err)
	}
}

func TestLinuxUpdateArtifactRejectsInvalidFiles(t *testing.T) {
	for _, problem := range []string{"missing", "tamper", "truncated", "size", "digest", "directory", "symlink_inside", "symlink_outside", "edition", "version", "platform", "format", "oversize"} {
		t.Run(problem, func(t *testing.T) {
			a, directory, m, executable := linuxUpdateArtifactFixture(t)
			path := filepath.Join(directory, "milvago-community-0.7.44-linux")
			var err error
			switch problem {
			case "missing":
				err = os.Remove(path)
			case "tamper":
				err = os.WriteFile(path, bytes.Repeat([]byte{'x'}, len(executable)), 0600)
			case "truncated":
				err = os.WriteFile(path, executable[:len(executable)-1], 0600)
			case "size":
				m.Size++
			case "digest":
				m.SHA256 = strings.Repeat("a", 64)
			case "directory", "symlink_inside", "symlink_outside":
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if problem == "directory" {
					err = os.Mkdir(path, 0700)
				} else {
					target := filepath.Join(directory, "raw-target")
					if problem == "symlink_outside" {
						target = filepath.Join(t.TempDir(), "raw-target")
					}
					if err = os.WriteFile(target, executable, 0600); err != nil {
						t.Fatal(err)
					}
					if err = os.Symlink(target, path); err != nil {
						t.Skip("symlinks unavailable on this test platform")
					}
				}
			case "edition":
				m.Edition = "../community"
			case "version":
				m.Version = "../../0.7.44"
			case "platform":
				m.Platform = "../linux"
			case "format":
				m.Format = "msi"
			case "oversize":
				m.Size = 128*1024*1024 + 1
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = a.releaseUpdateBundle(m); err == nil || a.releaseArtifactReady(m) {
				t.Fatal("invalid executable update was offered")
			}
		})
	}
}

func TestWindowsUpdateKeepsInstallerLocator(t *testing.T) {
	installerBundleFixture(t)
	a := &App{}
	installer, path, err := a.releaseBundle("windows")
	if err != nil {
		t.Fatal(err)
	}
	m := UpdateManifest{Edition: "community", Platform: "windows", Version: installer.Version, Format: "msi", SHA256: installer.SHA256, Size: installer.Size}
	update, updatePath, err := a.releaseUpdateBundle(m)
	if err != nil || update != installer || updatePath != path || !a.releaseArtifactReady(m) {
		t.Fatal("Windows MSI locator changed", err)
	}
}
