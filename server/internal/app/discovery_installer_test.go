package app

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestDiscoveryInstallerValidatesCompleteOptionalComponent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix executable modes required")
	}
	for _, edition := range []string{"community", "commercial"} {
		t.Run(edition, func(t *testing.T) {
			payload := t.TempDir()
			writeValidInstallerPayload(t, payload, edition)
			if err := validateInstallerPayload(payload, edition); err != nil {
				t.Fatal(err)
			}
			writePayloadELF(t, payload, "milvago-discovery-system", 0x3e, true)
			resources := []string{"install-discovery.py", "milvago-discovery.service", "milvago-discovery-enroll.service", "milvago-discovery-enroll.timer", "licenses/discovery/LICENSE", "licenses/discovery/NOTICE-ENGINE", "licenses/discovery/NOTICE-SOURCES"}
			for _, resource := range resources {
				if err := validateInstallerPayload(payload, edition); err == nil {
					t.Fatal("incomplete system component accepted")
				}
				name := filepath.Join(payload, filepath.FromSlash(resource))
				if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, []byte("fixture\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := validateInstallerPayload(payload, edition); err != nil {
				t.Fatal(err)
			}
			writePayloadELF(t, payload, "milvago-discovery-system", 0x28, true)
			if err := validateInstallerPayload(payload, edition); err == nil {
				t.Fatal("wrong architecture system component accepted")
			}
		})
	}
}

func TestDiscoveryInstallerRPMCarriesProtectedComponent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix executable modes required")
	}
	for _, tool := range []string{"rpm", "rpm2cpio", "cpio"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("RPM verifier tools not installed")
		}
	}
	resources := map[string][]byte{}
	modes := map[string]os.FileMode{"milvago-discovery-system": 0755, "install-discovery.py": 0755}
	for _, name := range []string{"install-discovery.py", "milvago-discovery.service", "milvago-discovery-enroll.service", "milvago-discovery-enroll.timer", "licenses/discovery/LICENSE", "licenses/discovery/NOTICE-ENGINE", "licenses/discovery/NOTICE-SOURCES"} {
		resources[name] = []byte("synthetic resource: " + name + "\n")
		if _, ok := modes[name]; !ok {
			modes[name] = 0644
		}
	}
	directory, artifact := createInstallerRPMFixtureWithPayload(t, func(payload string) {
		writePayloadELF(t, payload, "milvago-discovery-system", 0x3e, true)
		for name, body := range resources {
			file := filepath.Join(payload, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, body, modes[name]); err != nil {
				t.Fatal(err)
			}
		}
		body, err := os.ReadFile(filepath.Join(payload, "milvago-discovery-system"))
		if err != nil {
			t.Fatal(err)
		}
		resources["milvago-discovery-system"] = body
	})
	metadata, err := exec.Command("rpm", "-qp", "--qf", "[%{FILENAMES}|%{FILEUSERNAME}|%{FILEGROUPNAME}|%{FILEMODES:octal}\n]", artifact).Output()
	if err != nil {
		t.Fatal(err)
	}
	root := "/opt/milvago-" + Edition + "/"
	checked := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(metadata)), "\n") {
		fields := strings.Split(line, "|")
		if len(fields) != 4 {
			t.Fatal("invalid RPM file metadata")
		}
		name := strings.TrimPrefix(fields[0], root)
		want, ok := modes[name]
		if !ok {
			continue
		}
		mode, err := strconv.ParseUint(fields[3], 8, 32)
		if err != nil || mode&07777 != uint64(want) || fields[1] != "root" || fields[2] != "root" {
			t.Fatalf("unprotected discovery RPM asset: %s", name)
		}
		checked[name] = true
	}
	if len(checked) != len(resources) {
		t.Fatal("discovery RPM assets missing")
	}
	archive, err := exec.Command("rpm2cpio", artifact).Output()
	if err != nil {
		t.Fatal(err)
	}
	extracted := filepath.Join(directory, "discovery-extracted")
	if err := os.Mkdir(extracted, 0700); err != nil {
		t.Fatal(err)
	}
	unpack := exec.Command("cpio", "-id", "--quiet", "--no-absolute-filenames")
	unpack.Dir = extracted
	unpack.Stdin = bytes.NewReader(archive)
	if err := unpack.Run(); err != nil {
		t.Fatal(err)
	}
	for name, want := range resources {
		body, err := os.ReadFile(filepath.Join(extracted, "opt", "milvago-"+Edition, filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(body, want) {
			t.Fatalf("discovery RPM asset changed: %s", name)
		}
	}
	scripts, err := exec.Command("rpm", "-qp", "--scripts", artifact).Output()
	if err != nil {
		t.Fatal(err)
	}
	provision := root + "provision.json"
	if Edition == "commercial" {
		provision = "/etc/milvago-commercial/provision.json"
	}
	for _, hook := range []string{
		"python3 " + root + "install-discovery.py " + provision + " " + Edition + " || exit 1",
		"python3 " + root + "install-discovery.py --remove " + Edition,
		`if [ "$1" = 1 ] && [ "${MILVAGO_DISCOVERY_MANAGED:-0}" != 1 ]; then`,
	} {
		if !bytes.Contains(scripts, []byte(hook)) {
			t.Fatal("discovery RPM installation/removal guard missing")
		}
	}
}
