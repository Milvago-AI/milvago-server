package app

import (
	"strings"
	"testing"
)

func TestValidOrigin(t *testing.T) {
	valid := []string{
		"https://console.milvago.example",
		"https://console.milvago.example:8443",
		"http://localhost:4020",
		"http://127.0.0.1:4020",
		"http://[::1]:4020",
	}
	for _, v := range valid {
		if !validOrigin(v) {
			t.Errorf("expected valid: %q", v)
		}
	}
	invalid := []string{
		"",
		"http://evil.example",             // http non-loopback
		"https://x/path",                  // path
		"https://x?q=1",                   // query
		"https://x#frag",                  // fragment
		"https://user@x",                  // userinfo
		"https://",                        // no host
		"//evil.example",                  // scheme-relative
		"javascript:alert(1)",             // wrong scheme
		"ftp://x",                         // wrong scheme
		"https://x/",                      // trailing path
		"https://good.example\r\nHost: y", // CRLF injection
		"https://x?",                      // force query
		"https://x#",                      // empty fragment marker
		"https://x y",                     // whitespace
	}
	for _, v := range invalid {
		if validOrigin(v) {
			t.Errorf("expected invalid: %q", v)
		}
	}
}

func TestUpdateManifestXML(t *testing.T) {
	out, err := updateManifestXML("https://c.example", "0.4.0", "nfeckglpbmfpflcdfciakndkopnpaffc")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.HasPrefix(s, "<?xml") {
		t.Fatal("missing XML declaration")
	}
	for _, want := range []string{
		`codebase="https://c.example/ext/milvago.crx"`,
		`version="0.4.0"`,
		`appid="nfeckglpbmfpflcdfciakndkopnpaffc"`,
		`protocol="2.0"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("manifest missing %q; got:\n%s", want, s)
		}
	}
}

func TestUpdateManifestXMLEscapesInjection(t *testing.T) {
	// Defence in depth: even if a malicious origin reached the builder (it cannot,
	// validOrigin rejects it first), encoding/xml must escape it — no raw markup.
	out, err := updateManifestXML(`https://x"><script>alert(1)</script>`, "0.4.0", "id")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "<script>") {
		t.Fatalf("unescaped markup leaked into manifest:\n%s", s)
	}
}
