package app

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/google/rpmpack"
)

// The RPM is assembled in process: the server image carries no package builder
// and no shell. Scriptlets run on the endpoint under /bin/sh, as rpmbuild's did.

type installerRPMPlan struct {
	meta                     rpmpack.RPMMetaData
	files                    []rpmpack.RPMFile
	pre, post, preun, postun string
}

func rpmText(name, body string, mode uint) rpmpack.RPMFile {
	return rpmpack.RPMFile{Name: name, Body: []byte(body), Mode: mode, Owner: "root", Group: "root"}
}

func rpmDirectory(name string, mode uint) rpmpack.RPMFile {
	return rpmpack.RPMFile{Name: name, Mode: 040000 | mode, Owner: "root", Group: "root"}
}

// rpmConfigMigration moves milvago.toml once from /var/lib/<name>/config, which the
// agent account can write, to root's /etc/<name>, where the agent now reads it (the
// agent must not choose its own certificate authorities). Root never follows a link
// the agent may have planted in its state.
func rpmConfigMigration(name string) string {
	return `install -d -m 0755 -o root -g root /etc/` + name + ` || exit 1
python3 - /var/lib/` + name + ` /etc/` + name + ` <<'PY' || exit 1
import grp,os,stat,sys
state,etc=sys.argv[1],sys.argv[2]
group=grp.getgrnam('milvago-agent').gr_gid
def opendir(name,parent=None):
 try:return os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
 except OSError:return None
def move(directory,name,target):
 try:source=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
 except OSError:return
 info=os.fstat(source)
 if os.path.lexists(target) or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>1024*1024:
  os.close(source);return
 body=os.read(source,1024*1024)
 os.close(source)
 fd=os.open(target+'.new',os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o640)
 os.fchown(fd,0,group)
 with os.fdopen(fd,'wb') as out:out.write(body)
 os.replace(target+'.new',target)
 os.unlink(name,dir_fd=directory)
# Once only: a file the agent account drops in its state later is never promoted.
marker=os.path.join(etc,'.config-migrated')
if os.path.lexists(marker):raise SystemExit(0)
config=opendir(os.path.join(state,'config'))
if config is not None:
 move(config,'milvago.toml',os.path.join(etc,'milvago.toml'))
 certs=opendir('certs',config)
 if certs is not None:
  os.makedirs(os.path.join(etc,'certs'),mode=0o755,exist_ok=True)
  for name in os.listdir(certs):
   if name.endswith('.pem'):move(certs,name,os.path.join(etc,'certs',name))
os.close(os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644))
PY
`
}

func rpmRelations(names ...string) (rpmpack.Relations, error) {
	var out rpmpack.Relations
	for _, name := range names {
		relation, err := rpmpack.NewRelation(name)
		if err != nil {
			return nil, err
		}
		out = append(out, relation)
	}
	return out, nil
}

// newInstallerRPMPlan returns everything the package adds besides the release payload.
func newInstallerRPMPlan(edition, version string, provision []byte) (installerRPMPlan, error) {
	opposite := "commercial"
	if edition == "commercial" {
		opposite = "community"
	}
	// rpmbuild used to derive the glibc requirement from the binaries; rpmpack does not.
	// Measured on the 0.5.43 Linux binaries (2026-09-23): GLIBC_2.34 at most. Without it a
	// RHEL 8 host (glibc 2.28) installs the package, then every binary fails to start.
	// Re-measure when the Linux build image changes (deploy/Endpoint.Dockerfile).
	requires := []string{"systemd", "python3", "util-linux", "libc.so.6(GLIBC_2.34)(64bit)"}
	if edition == "commercial" {
		requires = append(requires, "python3-setools", "python3-libselinux", "policycoreutils-python-utils", "selinux-policy-devel", "checkpolicy", "make", "shadow-utils", "ca-certificates")
	}
	req, err := rpmRelations(requires...)
	if err != nil {
		return installerRPMPlan{}, err
	}
	conflicts, err := rpmRelations("milvago-" + opposite)
	if err != nil {
		return installerRPMPlan{}, err
	}
	p := installerRPMPlan{meta: rpmpack.RPMMetaData{
		Name: "milvago-" + edition, Version: version, Release: "1", Arch: "x86_64", OS: "linux",
		Summary:     "Milvago " + edition + " endpoint",
		Description: "Milvago endpoint with organization provisioning and encrypted per-user state.",
		Licence:     "LicenseRef-Milvago-" + edition, BuildTime: time.Now(),
		Requires: req, Conflicts: conflicts,
	}}
	if edition != "commercial" {
		// One machine identity served by a system service, as the MSI and install-browser.sh
		// do (audit of 2026-09-23). The former per-user unit could not work: ipc::serve binds
		// /run/milvago, which an ordinary user cannot create, and every user's agent competed
		// for the same socket and the same loopback extension ports.
		p.files = append(p.files,
			rpmText("/usr/lib/tmpfiles.d/milvago-community.conf", "d /var/lib/milvago-browser 0750 milvago-agent milvago-agent -\n", 0644),
			rpmText("/usr/lib/systemd/system/milvago-community.service", `[Unit]
Description=Milvago Agent Logger Community
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=milvago-agent
Group=milvago-agent
RuntimeDirectory=milvago
RuntimeDirectoryMode=0755
ExecStartPre=/opt/milvago-community/milvago-browser-agent bootstrap /var/lib/milvago-browser /opt/milvago-community/provision.json "%H"
ExecStart=/opt/milvago-community/milvago-browser-agent service /var/lib/milvago-browser
Restart=always
RestartSec=15
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
ReadWritePaths=/var/lib/milvago-browser
PrivateTmp=yes
UMask=0077
[Install]
WantedBy=multi-user.target
`, 0644))
		p.pre = "id -u milvago-agent >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin milvago-agent || exit 1\n"
		p.post = `systemd-tmpfiles --create /usr/lib/tmpfiles.d/milvago-community.conf || exit 1
python3 - <<'PY'
import json,os,pathlib,re
package=pathlib.Path('/opt/milvago-community')
chromium=(package/'extension-id.txt').read_text().strip()
gecko=(package/'extension-firefox-id.txt').read_text().strip()
if not re.fullmatch('[a-p]{32}',chromium) or not re.fullmatch(r'[a-z0-9.-]+@milvago\.app',gecko):raise SystemExit('Invalid extension identity')
manifest={'name':'app.milvago.browser','description':'Milvago browser policy bridge','path':str(package/'milvago-browser-agent'),'type':'stdio','allowed_origins':['chrome-extension://'+chromium+'/']}
# A umask 027 host would otherwise leave the directories and manifests unreadable to the browser.
os.umask(0o022)
def publish(name,body):
 directory=pathlib.Path(name);directory.mkdir(parents=True,exist_ok=True)
 (directory/'app.milvago.browser.json').write_text(json.dumps(body))
for name in ['/etc/opt/chrome/native-messaging-hosts','/etc/chromium/native-messaging-hosts','/etc/opt/edge/native-messaging-hosts','/etc/opt/brave/native-messaging-hosts']:publish(name,manifest)
manifest.pop('allowed_origins');manifest['allowed_extensions']=[gecko]
for name in ['/usr/lib/mozilla/native-messaging-hosts','/usr/lib64/mozilla/native-messaging-hosts']:publish(name,manifest)
PY
systemctl daemon-reload || exit 1
# Retire the per-user unit of earlier packages; its file left with the upgrade.
systemctl --global disable milvago-community.service >/dev/null 2>&1 || :
if command -v loginctl >/dev/null; then
 loginctl list-users --no-legend 2>/dev/null | while read -r uid account rest; do
  case "$uid" in ''|*[!0-9]*) continue;; esac
  if [ "$uid" -ge 1000 ] && [ -S "/run/user/$uid/bus" ]; then
   runuser -u "$account" -- env XDG_RUNTIME_DIR="/run/user/$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" systemctl --user stop milvago-community.service >/dev/null 2>&1 || :
   runuser -u "$account" -- env XDG_RUNTIME_DIR="/run/user/$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" systemctl --user daemon-reload >/dev/null 2>&1 || :
  fi
 done
fi
systemctl enable milvago-community.service || exit 1
if [ "$1" = 1 ]; then
 # A first installation replaces the identity an earlier, since removed, installation of
 # another organization left in /var/lib/milvago-browser (not owned by the package).
 runuser -u milvago-agent -- /opt/milvago-community/milvago-browser-agent bootstrap /var/lib/milvago-browser /opt/milvago-community/provision.json "$(uname -n)" --reprovision || exit 1
fi
` + rpmConfigMigration("milvago-browser") + `systemctl restart milvago-community.service || exit 1
`
		p.preun = `if [ "$1" = 0 ]; then
 systemctl disable --now milvago-community.service >/dev/null 2>&1 || :
 for directory in /etc/opt/chrome /etc/chromium /etc/opt/edge /etc/opt/brave; do rm -f "$directory/native-messaging-hosts/app.milvago.browser.json"; done
 rm -f /usr/lib/mozilla/native-messaging-hosts/app.milvago.browser.json /usr/lib64/mozilla/native-messaging-hosts/app.milvago.browser.json
fi
`
		p.postun = "systemctl daemon-reload >/dev/null 2>&1 || :\n"
		return p, nil
	}
	// Enterprise: system services own the device credential, the root collector
	// the verified anchor and OS attribution; the model filter is confined by SELinux.
	p.meta.Summary = "Milvago Enterprise machine endpoint"
	p.meta.Description = "Milvago machine browser bridge and trusted local native telemetry collector."
	p.files = append(p.files,
		rpmDirectory("/etc/milvago-commercial", 0755),
		rpmpack.RPMFile{Name: "/etc/milvago-commercial/provision.json", Body: provision, Mode: 0640, Owner: "root", Group: "milvago-agent", Type: rpmpack.ConfigFile | rpmpack.NoReplaceFile},
		rpmText("/usr/lib/tmpfiles.d/milvago-commercial.conf", `d /run/milvago 0755 milvago-agent milvago-agent -
d /var/lib/milvago-commercial 0750 milvago-agent milvago-agent -
d /var/lib/milvago-collector 0700 root root -
d /etc/claude-code 0755 root root -
d /etc/claude-code/managed-settings.d 0755 root root -
d /etc/codex 0755 root root -
`, 0644),
		rpmText("/usr/lib/systemd/system/milvago-commercial.service", `[Unit]
Description=Milvago Agent Logger Enterprise
After=network-online.target milvago-collector.service
Wants=network-online.target milvago-collector.service
[Service]
Type=simple
User=milvago-agent
Group=milvago-agent
ExecStartPre=/opt/milvago-commercial/milvago-commercial-bridge bootstrap /var/lib/milvago-commercial /etc/milvago-commercial/provision.json "%H"
ExecStart=/opt/milvago-commercial/milvago-commercial-bridge service /var/lib/milvago-commercial
Restart=always
RestartSec=15
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
ReadWritePaths=/var/lib/milvago-commercial /run/milvago
PrivateTmp=yes
UMask=0077
[Install]
WantedBy=multi-user.target
`, 0644),
		rpmText("/usr/lib/systemd/system/milvago-collector.service", `[Unit]
Description=Milvago Native Collector
After=systemd-tmpfiles-setup.service
[Service]
Type=simple
User=root
Group=milvago-agent
ExecStart=/opt/milvago-commercial/milvago-collector run
Restart=always
RestartSec=15
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
RuntimeDirectory=milvago-collector
RuntimeDirectoryMode=0755
ReadWritePaths=/var/lib/milvago-collector /etc/claude-code /etc/codex
RestrictAddressFamilies=AF_UNIX AF_INET
PrivateTmp=yes
UMask=0077
[Install]
WantedBy=multi-user.target
`, 0644),
		rpmDirectory("/etc/milvago-model-filter", 0750),
		rpmpack.RPMFile{Name: "/etc/milvago-model-filter/config.json", Body: []byte(`{"state_dir":"/var/lib/milvago-model-filter/state","provision_file":"/etc/milvago-model-filter/provision.json","hostname":"","bindings":[]}` + "\n"), Mode: 0600, Owner: "root", Group: "root", Type: rpmpack.ConfigFile | rpmpack.NoReplaceFile},
		rpmpack.RPMFile{Name: "/etc/milvago-model-filter/provision.json", Body: provision, Mode: 0600, Owner: "root", Group: "root", Type: rpmpack.ConfigFile | rpmpack.NoReplaceFile},
	)
	// --user-group: files and units name the milvago-agent group, which useradd creates
	// only by distribution default otherwise.
	p.pre = `test "$(getenforce 2>/dev/null)" = Enforcing || { echo 'Milvago native model confinement requires SELinux Enforcing.' >&2; exit 1; }
id -u milvago-agent >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin milvago-agent || exit 1
if [ -f /etc/systemd/system/milvago-model-filter.service ]; then
 systemctl stop milvago-model-filter.service || exit 1
fi
`
	p.post = `python3 - <<'PY'
import json, os, pathlib, socket, tempfile
p=pathlib.Path("/etc/milvago-model-filter/config.json")
c=json.loads(p.read_text())
if not c.get("hostname"):
 c["hostname"]=socket.gethostname()[:100]+"-filter"
 fd,temporary=tempfile.mkstemp(dir=p.parent,prefix=".config-")
 with os.fdopen(fd,"w") as output:
  json.dump(c,output)
 os.chmod(temporary,0o600)
 os.replace(temporary,p)
PY
configure_machinefilter() {
 /opt/milvago-commercial/register-model-filter.sh /etc/milvago-model-filter/config.json /opt/milvago-commercial/milvago-model-filter
}
# A registration refusal (a registered AI client still running, on upgrade) must not skip
# the bridge and collector steps below: it is reported, and the filter restarted, at the end.
filter_failed=
configure_machinefilter || filter_failed=1
id -u milvago-agent >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin milvago-agent || exit 1
systemd-tmpfiles --create /usr/lib/tmpfiles.d/milvago-commercial.conf || exit 1
if [ "$1" = 1 ]; then
 /opt/milvago-commercial/milvago-collector provision-json /opt/milvago-commercial/provision.json /var/lib/milvago-collector/provision.json --reprovision || exit 1
else
 /opt/milvago-commercial/milvago-collector provision-json /opt/milvago-commercial/provision.json /var/lib/milvago-collector/provision.json || exit 1
fi
python3 - <<'PY'
import json,os,pathlib,re
package=pathlib.Path('/opt/milvago-commercial')
chromium=(package/'extension-id.txt').read_text().strip()
gecko=(package/'extension-firefox-id.txt').read_text().strip()
if not re.fullmatch('[a-p]{32}',chromium) or not re.fullmatch(r'[a-z0-9.-]+@milvago\.app',gecko):raise SystemExit('Invalid extension identity')
manifest={'name':'app.milvago.browser','description':'Milvago browser policy bridge','path':str(package/'milvago-commercial-bridge'),'type':'stdio','allowed_origins':['chrome-extension://'+chromium+'/']}
# A umask 027 host would otherwise leave the directories and manifests unreadable to the browser.
os.umask(0o022)
def publish(name,body):
 directory=pathlib.Path(name);directory.mkdir(parents=True,exist_ok=True)
 (directory/'app.milvago.browser.json').write_text(json.dumps(body))
for name in ['/etc/opt/chrome/native-messaging-hosts','/etc/chromium/native-messaging-hosts','/etc/opt/edge/native-messaging-hosts','/etc/opt/brave/native-messaging-hosts']:publish(name,manifest)
manifest.pop('allowed_origins');manifest['allowed_extensions']=[gecko]
for name in ['/usr/lib/mozilla/native-messaging-hosts','/usr/lib64/mozilla/native-messaging-hosts']:publish(name,manifest)
PY
systemctl daemon-reload || exit 1
# Retire the previous RPM user bridge before the machine bridge owns IPC.
systemctl --global disable milvago-commercial.service >/dev/null 2>&1 || :
if command -v loginctl >/dev/null; then
 loginctl list-users --no-legend 2>/dev/null | while read -r uid account rest; do
  case "$uid" in ''|*[!0-9]*) continue;; esac
  if [ "$uid" -ge 1000 ] && [ -S "/run/user/$uid/bus" ]; then
   # Best effort: the per-user unit no longer exists, and stopping an unloaded unit exits 5.
   runuser -u "$account" -- env XDG_RUNTIME_DIR="/run/user/$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" systemctl --user stop milvago-commercial.service >/dev/null 2>&1 || :
   runuser -u "$account" -- env XDG_RUNTIME_DIR="/run/user/$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" systemctl --user daemon-reload >/dev/null 2>&1 || :
  fi
 done
fi
systemctl enable milvago-collector.service milvago-commercial.service || exit 1
if [ "$1" = 1 ]; then
 # A first installation replaces the identity an earlier, since removed, installation of
 # another organization left in /var/lib/milvago-commercial (not owned by the package).
 runuser -u milvago-agent -- /opt/milvago-commercial/milvago-commercial-bridge bootstrap /var/lib/milvago-commercial /etc/milvago-commercial/provision.json "$(uname -n)" --reprovision || exit 1
fi
` + rpmConfigMigration("milvago-commercial") + `systemctl restart milvago-collector.service milvago-commercial.service || exit 1
if [ -n "$filter_failed" ]; then
 systemctl start milvago-model-filter.service >/dev/null 2>&1 || :
 echo 'Milvago: model filter registration failed (see above); the filter was restarted with its previous registration.' >&2
 [ "$1" = 1 ] && exit 1
fi
`
	// An erase must always be possible: every step is best effort and says what it left.
	// Failing here made rpm -e impossible short of --nopreun (the same class of defect as
	// a Windows uninstall that could never succeed).
	p.preun = `if [ "$1" = 0 ]; then
 /opt/milvago-commercial/register-model-filter.sh --remove /etc/milvago-model-filter/config.json /opt/milvago-commercial/milvago-model-filter || echo 'Milvago: model filter teardown incomplete; check semodule -l and semanage.' >&2
 systemctl disable --now milvago-commercial.service milvago-collector.service >/dev/null 2>&1 || :
 for directory in /etc/opt/chrome /etc/chromium /etc/opt/edge /etc/opt/brave; do rm -f "$directory/native-messaging-hosts/app.milvago.browser.json"; done
 rm -f /usr/lib/mozilla/native-messaging-hosts/app.milvago.browser.json /usr/lib64/mozilla/native-messaging-hosts/app.milvago.browser.json
fi
`
	p.postun = "systemctl daemon-reload >/dev/null 2>&1 || :\n"
	return p, nil
}

func buildInstallerRPM(directory, source string, provision InstallerProvision) (string, error) {
	payload := filepath.Join(directory, "payload")
	if err := os.Mkdir(payload, 0700); err != nil {
		return "", err
	}
	if err := extractInstallerPayload(source, payload); err != nil {
		return "", err
	}
	if err := validateInstallerPayload(payload, Edition); err != nil {
		return "", err
	}
	raw, err := readConfined(filepath.Join(directory, fileProvisionJSON))
	if err != nil {
		return "", err
	}
	plan, err := newInstallerRPMPlan(Edition, provision.Version, raw)
	if err != nil {
		return "", err
	}
	rpm, err := rpmpack.NewRPM(plan.meta)
	if err != nil {
		return "", err
	}
	root := "/opt/milvago-" + Edition
	// The deployment key is organization-wide and durable: never world-readable. The
	// Community service and its %post bootstrap run as milvago-agent, which reads it
	// through the group, exactly as Enterprise does for /etc/milvago-commercial
	// (audit of 2026-09-24: 0644 handed it to every local user of a managed machine).
	provisionFile := rpmpack.RPMFile{Name: root + "/" + fileProvisionJSON, Body: raw, Mode: 0640, Owner: "root", Group: "milvago-agent"}
	if Edition == "commercial" {
		provisionFile = rpmText(root+"/"+fileProvisionJSON, string(raw), 0600)
	}
	marker, _ := json.Marshal(map[string]string{"format": "rpm", "edition": Edition, "scope": "machine"})
	files := map[string]rpmpack.RPMFile{}
	add := func(file rpmpack.RPMFile) { files[file.Name] = file }
	add(rpmDirectory(root, 0755))
	err = filepath.WalkDir(payload, func(file string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || file == payload {
			return walkErr
		}
		relative, err := filepath.Rel(payload, file)
		if err != nil {
			return err
		}
		name := path.Join(root, filepath.ToSlash(relative))
		if entry.IsDir() {
			add(rpmDirectory(name, 0755))
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("invalid installer payload file")
		}
		body, err := readConfined(file)
		if err != nil {
			return err
		}
		mode := uint(0644)
		if info.Mode()&0111 != 0 {
			mode = 0755
		}
		add(rpmpack.RPMFile{Name: name, Body: body, Mode: mode, Owner: "root", Group: "root"})
		return nil
	})
	if err != nil {
		return "", err
	}
	// Added after the payload so the server's provisioning always wins over the release's.
	add(provisionFile)
	add(rpmText(root+"/edition.txt", Edition, 0644))
	add(rpmText(root+"/installation.json", string(marker), 0644))
	for _, file := range plan.files {
		add(file)
	}
	for _, file := range files {
		rpm.AddFile(file)
	}
	// rpmpack records the file bytes as the archive size; rpm2cpio and rpm expect the
	// uncompressed cpio length (newc: 110-byte header, name, data, each 4-aligned).
	align := func(n int) int { return (n + 3) &^ 3 }
	archive := align(110 + len("TRAILER!!!") + 1)
	for name, file := range files {
		archive += align(110+len(name)+1) + align(len(file.Body))
	}
	rpm.AddCustomSig(0x03ef, rpmpack.EntryInt32([]int32{int32(archive)}))
	rpm.AddPrein(plan.pre)
	rpm.AddPostin(plan.post)
	rpm.AddPreun(plan.preun)
	rpm.AddPostun(plan.postun)
	result := filepath.Join(directory, "milvago.rpm")
	output, err := createConfined(result, 0600)
	if err != nil {
		return "", err
	}
	if err = rpm.Write(output); err != nil {
		output.Close()
		return "", err
	}
	return result, output.Close()
}
