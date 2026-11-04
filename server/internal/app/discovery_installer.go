package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func discoveryInstallerPayload(payload string) (bool, error) {
	_, err := os.Lstat(filepath.Join(payload, "milvago-discovery-system"))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, name := range []string{"install-discovery.py", "milvago-discovery.service", "milvago-discovery-enroll.service", "milvago-discovery-enroll.timer", "licenses/discovery/LICENSE", "licenses/discovery/NOTICE-ENGINE", "licenses/discovery/NOTICE-SOURCES"} {
		info, err := os.Lstat(filepath.Join(payload, filepath.FromSlash(name)))
		if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
			return false, fmt.Errorf("invalid discovery installer resource: %s", name)
		}
	}
	return true, nil
}

// Older signed bundles remain usable. New bundles carry their own protected
// installer; it never promotes the bridge's writable device identity.
func discoveryRPMHook(edition string) string {
	root := "/opt/milvago-" + edition
	provision := root + "/provision.json"
	if edition == "commercial" {
		provision = "/etc/milvago-commercial/provision.json"
	}
	return "if [ -x " + root + "/milvago-discovery-system ]; then\n python3 " + root + "/install-discovery.py " + provision + " " + edition + " || exit 1\n if [ -f /etc/milvago-discovery/installation.json ]; then export MILVAGO_DISCOVERY_MANAGED=1; fi\nfi\n"
}

func discoveryRPMFinalize(p installerRPMPlan, edition string) installerRPMPlan {
	p.post = discoveryRPMHook(edition) + strings.ReplaceAll(p.post, `if [ "$1" = 1 ]; then`, `if [ "$1" = 1 ] && [ "${MILVAGO_DISCOVERY_MANAGED:-0}" != 1 ]; then`)
	p.preun = strings.Replace(p.preun, "if [ \"$1\" = 0 ]; then\n", "if [ \"$1\" = 0 ]; then\n systemctl disable --now milvago-discovery-enroll.timer milvago-discovery.service >/dev/null 2>&1 || :\n systemctl stop milvago-discovery-enroll.service >/dev/null 2>&1 || :\n", 1)
	p.preun = strings.Replace(p.preun, "if [ \"$1\" = 0 ]; then\n", "if [ \"$1\" = 0 ]; then\n if [ -f /opt/milvago-"+edition+"/install-discovery.py ]; then python3 /opt/milvago-"+edition+"/install-discovery.py --remove "+edition+" >/dev/null 2>&1 || :; fi\n", 1)
	return p
}
