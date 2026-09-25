package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpdateSignedPackageFormat(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MILVAGO_INSTALLER_DIRECTORY", dir)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32))
	a := &App{}
	a.config.UpdatePublicKey = key.Public().(ed25519.PublicKey)
	base := UpdateManifest{Version: "0.3.1", Edition: "community", Platform: "windows", Protocol: 2, SHA256: strings.Repeat("a", 64), Size: 128 * 1024 * 1024, ExpiresAt: time.Now().Add(time.Hour), Artifact: "/v2/update/artifact/" + strings.Repeat("a", 64)}
	write := func(m UpdateManifest, trailing bool, tamper bool) {
		t.Helper()
		payload, _ := json.Marshal(m)
		if trailing {
			payload = append(payload, []byte(" {}")...)
		}
		sig := ed25519.Sign(key, payload)
		if tamper {
			sig[0] ^= 1
		}
		raw, _ := json.Marshal(signedEnvelope{base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(sig)})
		if e := os.WriteFile(filepath.Join(dir, "community-"+m.Platform+"-update.json"), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, format := range []string{"", "binary", "msi"} {
		m := base
		m.Format = format
		write(m, false, false)
		_, actual, e := a.readUpdateManifest("community", "windows")
		if e != nil || actual.Format == "" {
			t.Fatal("valid signed package or legacy binary rejected", e)
		}
	}
	for _, name := range []string{"unknown", "linux_msi", "oversize", "edition", "signature", "trailing"} {
		t.Run(name, func(t *testing.T) {
			m := base
			m.Format = "msi"
			switch name {
			case "unknown":
				m.Format = "exe"
			case "linux_msi":
				m.Platform = "linux"
			case "oversize":
				m.Size++
			case "edition":
				m.Edition = "commercial"
			}
			write(m, name == "trailing", name == "signature")
			if _, _, e := a.readUpdateManifest("community", m.Platform); e == nil {
				t.Fatal("invalid release accepted")
			}
		})
	}
}
