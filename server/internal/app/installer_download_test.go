package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/rpmpack"
)

func TestInstallerArchiveBoundaries(t *testing.T) {
	for _, test := range []struct {
		name string
		kind byte
		ok   bool
	}{
		{"agent", tar.TypeReg, true}, {"extension/manifest.json", tar.TypeReg, true},
		{"../outside", tar.TypeReg, false}, {"/outside", tar.TypeReg, false}, {"nested/../../outside", tar.TypeReg, false},
		{"agent", tar.TypeSymlink, false}, {"agent", tar.TypeLink, false}, {"C:\\outside", tar.TypeReg, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			source := filepath.Join(directory, "payload.tar.gz")
			file, err := os.Create(source)
			if err != nil {
				t.Fatal(err)
			}
			compressed := gzip.NewWriter(file)
			archive := tar.NewWriter(compressed)
			header := &tar.Header{Name: test.name, Typeflag: test.kind, Mode: 0755}
			if test.kind == tar.TypeReg {
				header.Size = 4
			} else {
				header.Linkname = "outside"
			}
			if err = archive.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if test.kind == tar.TypeReg {
				archive.Write([]byte("test"))
			}
			archive.Close()
			compressed.Close()
			file.Close()
			target := filepath.Join(directory, "target")
			os.Mkdir(target, 0700)
			err = extractInstallerPayload(source, target)
			if (err == nil) != test.ok {
				t.Fatalf("allowed=%v error=%v", test.ok, err)
			}
			if _, err = os.Stat(filepath.Join(directory, "outside")); !os.IsNotExist(err) {
				t.Fatal("archive escaped destination")
			}
		})
	}
}

func exitStderr(err error) string {
	if exit, ok := err.(*exec.ExitError); ok {
		return string(exit.Stderr)
	}
	return ""
}

func writePayloadELF(t *testing.T, directory, name string, machine byte, executable bool) {
	t.Helper()
	mode := os.FileMode(0644)
	if executable {
		mode = 0755
	}
	header := make([]byte, 20)
	copy(header, "\x7fELF")
	header[4], header[5], header[18], header[19] = 2, 1, machine, 0
	if err := os.WriteFile(filepath.Join(directory, name), header, mode); err != nil {
		t.Fatal(err)
	}
}
func writeValidInstallerPayload(t *testing.T, directory, edition string) {
	t.Helper()
	agent := "milvago-browser-agent"
	if edition == "commercial" {
		agent = "milvago-commercial-bridge"
	}
	writePayloadELF(t, directory, agent, 0x3e, true)
	writePayloadELF(t, directory, "milvago-updater", 0x3e, true)
	if edition == "commercial" {
		writePayloadELF(t, directory, "milvago-model-filter", 0x3e, true)
		writePayloadELF(t, directory, "milvago-collector", 0x3e, true)
		if err := os.Mkdir(filepath.Join(directory, "selinux"), 0755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"register-model-filter.sh", "selinux/milvago_filter.te", "selinux/milvago_filter.fc"} {
			if err := os.WriteFile(filepath.Join(directory, filepath.FromSlash(name)), []byte("fixture"), 0755); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "agent-session.sh"), []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "extension-id.txt"), []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"), 0644); err != nil {
		t.Fatal(err)
	}
}
func TestInstallerPayloadValidation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executable mode validation requires a Unix filesystem")
	}

	for _, edition := range []string{"community", "commercial"} {
		t.Run(edition, func(t *testing.T) {

			directory := t.TempDir()
			writeValidInstallerPayload(t, directory, edition)
			if err := validateInstallerPayload(directory, edition); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"missing agent", func(t *testing.T, directory string) {
			if err := os.Remove(filepath.Join(directory, "milvago-browser-agent")); err != nil {
				t.Fatal(err)
			}
		}},
		{"non executable updater", func(t *testing.T, directory string) {
			if err := os.Chmod(filepath.Join(directory, "milvago-updater"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong executable format", func(t *testing.T, directory string) {
			writePayloadELF(t, directory, "milvago-browser-agent", 0x28, true)
		}},
		{"non executable session", func(t *testing.T, directory string) {
			if err := os.Chmod(filepath.Join(directory, "agent-session.sh"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"invalid extension identity", func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "extension-id.txt"), []byte("invalid\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {

			directory := t.TempDir()
			writeValidInstallerPayload(t, directory, "community")
			test.mutate(t, directory)
			if err := validateInstallerPayload(directory, "community"); err == nil {
				t.Fatal("invalid payload accepted")
			}
		})
	}
}

func TestInstallerRPMPlan(t *testing.T) {
	joined := func(p installerRPMPlan) string {
		all := []string{p.pre, p.post, p.preun, p.postun}
		for _, f := range p.files {
			all = append(all, f.Name, string(f.Body))
		}
		for _, r := range p.meta.Requires {
			all = append(all, r.Name)
		}
		return strings.Join(all, "\n")
	}
	commercial, err := newInstallerRPMPlan("commercial", "0.5.0", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	spec := joined(commercial)
	for _, required := range []string{
		"/usr/lib/systemd/system/milvago-commercial.service", "/usr/lib/systemd/system/milvago-collector.service",
		"User=root\nGroup=milvago-agent", "User=milvago-agent\nGroup=milvago-agent", "provision-json",
		"/etc/claude-code", "/etc/codex", "WantedBy=multi-user.target", "ProtectHome=read-only",
		"python3-setools", "selinux-policy-devel", "/etc/milvago-model-filter/config.json", "/etc/milvago-model-filter/provision.json",
		"configure_machinefilter || filter_failed=1", "register-model-filter.sh --remove", "gethostname()", "bindings",
		// The agent account keeps no capability, and reads its configuration from root's /etc.
		"CapabilityBoundingSet=\nReadWritePaths=/var/lib/milvago-commercial", "SystemCallFilter=@system-service\n",
		"/var/lib/milvago-commercial /etc/milvago-commercial <<'PY'", "os.O_NONBLOCK,dir_fd=directory", "st_nlink!=1", "ExecStart=/opt/milvago-commercial/milvago-collector run\n",
	} {
		if !strings.Contains(spec, required) {
			t.Fatalf("system RPM missing %q", required)
		}
	}
	for _, forbidden := range []string{"/usr/lib/systemd/user", "ExecStart=/opt/milvago-commercial/agent-session.sh", "WantedBy=default.target", "chmod 777", "rm -rf"} {
		if strings.Contains(spec, forbidden) {
			t.Fatalf("user service leaked into system RPM: %q", forbidden)
		}
	}
	if !strings.Contains(commercial.pre, "Enforcing") {
		t.Fatal("SELinux prerequisite must run before file installation")
	}
	// An erase must always be possible, and a first install must take over an identity an
	// earlier installation of another organization left behind (audit of 2026-09-23).
	for _, p := range []installerRPMPlan{commercial} {
		if strings.Contains(p.preun, "exit 1") || strings.Contains(p.postun, "exit 1") {
			t.Fatalf("an erase scriptlet can fail: %q %q", p.preun, p.postun)
		}
	}
	if !strings.Contains(commercial.post, "bootstrap /var/lib/milvago-commercial /etc/milvago-commercial/provision.json \"$(uname -n)\" --reprovision") || strings.Contains(commercial.post, "done || exit 1") {
		t.Fatal("first install must reprovision the bridge, and the per-user loop must not fail the install")
	}
	if !strings.Contains(commercial.post, "filter_failed=1") || !strings.Contains(commercial.pre, "--user-group") {
		t.Fatal("filter registration must not skip the bridge and collector steps; the service group must be created")
	}
	for _, f := range commercial.files {
		if strings.HasPrefix(f.Name, "/etc/milvago-model-filter/") && (f.Mode != 0600 || f.Type != rpmpack.ConfigFile|rpmpack.NoReplaceFile) {
			t.Fatalf("model filter configuration must be private and preserved: %s", f.Name)
		}
	}
	community, err := newInstallerRPMPlan("community", "0.5.0", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	spec = joined(community)
	// One machine service owns /run/milvago: a per-user unit could not create it, and several
	// users' agents raced for the same socket and loopback ports (audit of 2026-09-23).
	for _, required := range []string{
		"/usr/lib/systemd/system/milvago-community.service", "User=milvago-agent\nGroup=milvago-agent",
		"RuntimeDirectory=milvago\n", "service /var/lib/milvago-browser", "WantedBy=multi-user.target",
		"--global disable milvago-community.service", "/etc/opt/chrome/native-messaging-hosts", "os.umask(0o022)",
		"bootstrap /var/lib/milvago-browser /opt/milvago-community/provision.json \"$(uname -n)\" --reprovision",
	} {
		if !strings.Contains(spec, required) {
			t.Fatalf("Community RPM missing %q", required)
		}
	}
	if strings.Contains(spec, "/usr/lib/systemd/user") || strings.Contains(spec, "agent-session.sh") || !strings.Contains(community.pre, "--user-group") {
		t.Fatal("Community RPM still packages a per-user agent, or does not create the service group")
	}
	if strings.Contains(community.preun+community.postun, "exit 1") {
		t.Fatal("an erase must never fail")
	}
	for _, p := range []installerRPMPlan{community, commercial} {
		if !strings.Contains(joined(p), "libc.so.6(GLIBC_2.34)(64bit)") {
			t.Fatalf("%s RPM does not declare the glibc its binaries need", p.meta.Name)
		}
	}
	for _, forbidden := range []string{"milvago-collector", "model-filter", "selinux", "milvago-commercial"} {
		if strings.Contains(spec, forbidden) {
			t.Fatalf("Enterprise component in Community RPM: %q", forbidden)
		}
	}
}
func TestModelFilterPayloadEditionBoundary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix executable modes required")
	}
	commercial := t.TempDir()
	writeValidInstallerPayload(t, commercial, "commercial")
	if err := os.Remove(filepath.Join(commercial, "milvago-model-filter")); err != nil {
		t.Fatal(err)
	}
	if validateInstallerPayload(commercial, "commercial") == nil {
		t.Fatal("accepted missing native filter")
	}
	community := t.TempDir()
	writeValidInstallerPayload(t, community, "community")
	writePayloadELF(t, community, "milvago-model-filter", 0x3e, true)
	if validateInstallerPayload(community, "community") == nil {
		t.Fatal("Enterprise filter leaked into Community")
	}
}

func TestInstallerRPMBuildArtifact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("payload executable modes require Linux")
	}
	directory := t.TempDir()
	staged := filepath.Join(directory, "fixture")
	if err := os.Mkdir(staged, 0755); err != nil {
		t.Fatal(err)
	}
	writeValidInstallerPayload(t, staged, Edition)
	source := filepath.Join(directory, "source.tar.gz")
	file, err := os.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)
	err = filepath.WalkDir(staged, func(path string, entry os.DirEntry, walkErr error) error {
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
		name, e := filepath.Rel(staged, path)
		if e != nil {
			return e
		}
		header, e := tar.FileInfoHeader(info, "")
		if e != nil {
			return e
		}
		header.Name = filepath.ToSlash(name)
		if e = archive.WriteHeader(header); e != nil {
			return e
		}
		content, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		_, e = archive.Write(content)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err = compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "provision.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := buildInstallerRPM(directory, source, InstallerProvision{Version: "0.4.0"})
	if err != nil {
		t.Fatal(err)
	}
	// Every scriptlet must parse under the /bin/sh rpm runs it with (dash on Debian).
	plan, err := newInstallerRPMPlan(Edition, "0.4.0", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string]string{"pre": plan.pre, "post": plan.post, "preun": plan.preun, "postun": plan.postun} {
		check := exec.Command("sh", "-n")
		check.Stdin = strings.NewReader(script)
		if out, err := check.CombinedOutput(); err != nil {
			t.Fatalf("%%%s does not parse: %v %s", name, err, out)
		}
	}
	// The server builds without any tool; rpm itself is only the independent verifier.
	if _, err := os.Stat("/usr/bin/rpm"); err != nil {
		t.Skip("rpm verifier not installed")
	}
	files, err := exec.Command("rpm", "-qpl", result).Output()
	if err != nil {
		t.Fatal(err)
	}
	hasCollector := bytes.Contains(files, []byte("/opt/milvago-commercial/milvago-collector"))
	if hasCollector != (Edition == "commercial") {
		t.Fatalf("wrong native collector edition: %s", files)
	}
	if Edition == "commercial" {
		for _, path := range []string{"/usr/lib/systemd/system/milvago-commercial.service", "/usr/lib/systemd/system/milvago-collector.service", "/usr/lib/tmpfiles.d/milvago-commercial.conf"} {
			if !bytes.Contains(files, []byte(path)) {
				t.Fatalf("RPM lacks system service %s", path)
			}
		}
		if bytes.Contains(files, []byte("/usr/lib/systemd/user/")) {
			t.Fatal("Enterprise RPM still packages a per-user service")
		}
		extract := filepath.Join(directory, "extracted")
		if err := os.Mkdir(extract, 0700); err != nil {
			t.Fatal(err)
		}
		payload, err := exec.Command("rpm2cpio", result).Output()
		if err != nil {
			t.Fatal(err, exitStderr(err))
		}
		// rpmpack stores absolute payload names; keep extraction inside the test directory.
		unpack := exec.Command("cpio", "-id", "--quiet", "--no-absolute-filenames")
		unpack.Dir = extract
		unpack.Stdin = bytes.NewReader(payload)
		if err := unpack.Run(); err != nil {
			t.Fatal(err)
		}
		unit, err := os.ReadFile(filepath.Join(extract, "usr/lib/systemd/system/milvago-collector.service"))
		if err != nil {
			t.Fatal(err)
		}
		// Root serves its socket from its own runtime directory, never the agent-owned /run/milvago.
		if !bytes.Contains(unit, []byte("User=root\nGroup=milvago-agent")) || !bytes.Contains(unit, []byte("ExecStart=/opt/milvago-commercial/milvago-collector")) ||
			!bytes.Contains(unit, []byte("RuntimeDirectory=milvago-collector\n")) || bytes.Contains(unit, []byte("/run/milvago")) {
			t.Fatalf("wrong extracted collector unit: %s", unit)
		}
	}
	hasFilter := bytes.Contains(files, []byte("/opt/milvago-commercial/milvago-model-filter"))
	hasConfig := bytes.Contains(files, []byte("/etc/milvago-model-filter/config.json"))
	if hasFilter != (Edition == "commercial") || hasConfig != (Edition == "commercial") {
		t.Fatalf("wrong edition RPM contents: %s", files)
	}
	scripts, err := exec.Command("rpm", "-qp", "--scripts", result).Output()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(scripts, []byte("configure_machinefilter")) != (Edition == "commercial") {
		t.Fatal("wrong edition RPM registration scripts")
	}
}
