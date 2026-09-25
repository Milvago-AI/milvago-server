package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// TestLicenseGateFollowsTheMux sends the path tricks an attacker would try through a
// ServeMux shaped like the application's: the gate must refuse every request the mux
// hands to a gated route, whatever the spelling.
func TestLicenseGateFollowsTheMux(t *testing.T) {
	mux := http.NewServeMux()
	ok := func(http.ResponseWriter, *http.Request) {}
	for _, p := range []string{
		"GET /api/session", "POST /api/session/organization", "PUT /api/license", "POST /api/license/request",
		"GET /api/bootstrap", "GET /api/setup", "POST /api/setup/complete", "GET /api/members",
		"GET /api/roles/{name}/members", "PUT /api/roles/{name}", "GET /api/shadow/events/{id}",
		"GET /auth/login", "GET /auth/callback", "GET /auth/device", "POST /auth/device", "POST /v1/enroll",
		"GET /v2/update/artifact/{sha256}", "POST /v2/install", "GET /v3/policy", "GET /ext/milvago.crx",
		"POST " + mcpPath, "GET /.well-known/oauth-protected-resource", "/api/", "/v1/", "/v2/", "/",
	} {
		mux.HandleFunc(p, ok)
	}
	for _, test := range []struct {
		method, target string
		gated          bool
	}{
		{"GET", "/api/session", false},
		{"HEAD", "/api/session", false},
		{"POST", "/api/session/organization", false},
		{"PUT", "/api/license", false},
		{"GET", "/api/bootstrap", false},
		{"GET", "/api/setup", false},
		{"POST", "/api/setup/complete", false},
		{"GET", "/auth/login", false},
		{"GET", "/auth/callback", false},
		{"GET", "/", false},
		{"GET", "/assets/index.js", false},
		{"GET", "/API/members", false}, // the mux is case-sensitive: this is the console's static route
		{"GET", "/.well-known/oauth-protected-resource", false},
		{"POST", "/api/session", true},
		{"POST", "/api/license/request", true},
		{"GET", "/api/members", true},
		{"GET", "/api/members/", true},
		{"OPTIONS", "/api/members", true},
		{"GET", "/api/setup/../members", true},
		{"GET", "/api/setup/../../api/members", true},
		{"GET", "//api/members", true},
		{"GET", "/api/session/../members", true},
		{"PUT", "/api/license/../members/1/role", true},
		{"GET", "/api/setup/%2e%2e/members", true},
		{"GET", "/api/setup%2F..%2Fmembers", true},
		{"CONNECT", "/api/members/../setup", true},
		// The mux unescapes each segment: %61pi is api.
		{"GET", "/%61pi/members", true},
		// ..%2F stays inside one wildcard segment for the mux, while path.Clean on the
		// decoded path climbs out of /api entirely.
		{"GET", "/api/roles/..%2F..%2F..%2Fsetup/members", true},
		{"GET", "/api/shadow/events/..%2F..%2F..%2F..%2Fx", true},
		{"PUT", "/%61pi/roles/..%2F..%2Fx", true},
		{"GET", "/v2/update/artifact/..%2F..%2F..%2F..%2Fx", true},
		{"GET", "/auth/device", true},
		{"POST", "/auth/device", true},
		{"POST", "/v1/enroll", true},
		{"POST", "/v2/install", true},
		{"GET", "/v3/policy", true},
		{"GET", "/ext/milvago.crx", true},
		{"POST", mcpPath, true},
		{"GET", "/api", true},
		{"GET", "/v1", true},
	} {
		r := httptest.NewRequest(test.method, test.target, nil)
		_, pattern := mux.Handler(r)
		if licenseGated(pattern) != test.gated {
			t.Errorf("%s %s (routed to %q) gated=%v", test.method, test.target, pattern, !test.gated)
		}
	}
}

// TestLicenseForgery tries the token-level attacks against verifyLicense.
func TestLicenseForgery(t *testing.T) {
	key := useTestLicenseKey(t)
	year := time.Now().Add(365 * 24 * time.Hour)
	valid := signLicense(t, key, jose.EdDSA, testLicense("enterprise", testInstance, year, 10))
	want, e := verifyLicense(valid, testInstance)
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(valid, ".")
	enc := base64.RawURLEncoding.EncodeToString
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	compact := func(signer ed25519.PrivateKey, header map[string]any, body []byte) string {
		h, _ := json.Marshal(header)
		input := enc(h) + "." + enc(body)
		return input + "." + enc(ed25519.Sign(signer, []byte(input)))
	}
	jwk, _ := jose.JSONWebKey{Key: attacker.Public()}.MarshalJSON()
	unlimited := strings.Replace(string(payload), `"max_devices":10`, `"max_devices":0`, 1)
	duplicate := strings.Replace(string(payload), `"instance":`, `"instance":"i-ffffffffffffffffffffffffffffffff","instance":`, 1)
	jsonSerialization, _ := json.Marshal(map[string]string{"protected": parts[0], "payload": parts[1], "signature": parts[2]})
	hostile := map[string]string{
		"attacker key embedded as jwk":   compact(attacker, map[string]any{"alg": "EdDSA", "jwk": json.RawMessage(jwk)}, payload),
		"kid naming another key":         compact(attacker, map[string]any{"alg": "EdDSA", "kid": "../../license-private.key"}, payload),
		"x5u to an attacker certificate": compact(attacker, map[string]any{"alg": "EdDSA", "x5u": "https://attacker.example.test/cert.pem"}, payload),
		"jku to an attacker key set":     compact(attacker, map[string]any{"alg": "EdDSA", "jku": "https://attacker.example.test/jwks.json"}, payload),
		// Signed with the real key: an unknown critical header is refused all the same.
		"unknown crit header":           compact(key, map[string]any{"alg": "EdDSA", "crit": []string{"x-unlimited"}, "x-unlimited": true}, payload),
		"alg spelled otherwise":         compact(key, map[string]any{"alg": "Ed25519"}, payload),
		"JWS JSON serialization":        string(jsonSerialization),
		"extra segment":                 valid + "." + parts[2],
		"empty extra segment":           valid + ".",
		"missing signature":             parts[0] + "." + parts[1] + ".",
		"quota rewritten, old signature": parts[0] + "." + enc([]byte(unlimited)) + "." + parts[2],
		// Duplicate keys only matter to a signer; the issuer marshals a struct, so it
		// never emits them (licensing/main_test.go, TestClaimsCannotBeInjected).
		"duplicate instance claim, attacker": compact(attacker, map[string]any{"alg": "EdDSA"}, []byte(duplicate)),
	}
	for name, raw := range hostile {
		t.Run(name, func(t *testing.T) {
			if c, e := verifyLicense(raw, testInstance); e == nil {
				t.Fatalf("licence accepted: %+v", c)
			}
		})
	}
	// Encodings that go-jose or base64 tolerate may be accepted, but only as the very
	// same licence: nothing an attacker can re-spell changes what it grants.
	lastSig := parts[2][len(parts[2])-1]
	flipped := byte('A')
	if lastSig == 'A' {
		flipped = 'B'
	}
	for name, raw := range map[string]string{
		"surrounding whitespace":            "\n\t " + valid + " \r\n",
		"newline inside the payload":        parts[0] + "." + parts[1][:10] + "\n" + parts[1][10:] + "." + parts[2],
		"padded segments":                   parts[0] + "==." + parts[1] + "." + parts[2] + "==",
		"non-canonical signature tail bits": parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-1] + string(flipped),
	} {
		t.Run(name, func(t *testing.T) {
			if c, e := verifyLicense(raw, testInstance); e == nil && !reflect.DeepEqual(c, want) {
				t.Fatalf("re-spelled licence grants something else: %+v", c)
			}
		})
	}
}
