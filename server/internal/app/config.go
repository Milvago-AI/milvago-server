package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type Config struct {
	// Role selects process responsibilities independently of the database role.
	// Empty preserves the historical combined process for hand-built configs.
	Role                                                                                         string
	PublisherURL, PublisherCredential                                                            string
	PublisherPublicKey                                                                           ed25519.PublicKey
	MetricsToken                                                                                 string
	OTelHTTPHosts                                                                                []string
	AdminClientID, AdminClientSecret                                                             string
	DatabaseURL, MigrationURL, RuntimeRole, AppURL, Issuer, InternalOIDC, ClientID, ClientSecret string
	BootstrapEmail, OrganizationName, StaticDir, Listen, PublicURL                               string
	SessionCipher                                                                                cipher.AEAD
	// ContentKeys holds the content-encryption roots by version and ContentVersion
	// names the one new ciphertext is sealed with. Separate from SESSION_KEY on
	// purpose: a session is disposable, so rotating its key costs one sign-in,
	// while sealed prompt content and deployment keys are durable. Sharing one root
	// made the cheap rotation impossible to perform without destroying the rest.
	ContentKeys     map[int][]byte
	ContentVersion  int
	UpdatePublicKey ed25519.PublicKey
	CollectorRoots  *x509.CertPool
	SigningKey      ed25519.PrivateKey
	SecureCookies   bool
	// ShadowMetrics exposes GET /api/shadow/metrics. On by default; set
	// MILVAGO_SHADOW_METRICS to 0/false/off/no to close the route on this instance.
	ShadowMetrics bool
	// MCPDisabled closes the Enterprise MCP endpoint on this instance. Set
	// MILVAGO_MCP to 0/false/off/no.
	//
	// The field is negative, unlike ShadowMetrics, and deliberately so: the zero
	// value has to mean "the endpoint the operator asked for is served". A
	// positively-named flag would be false in every hand-built Config -- the test
	// fixtures included -- and would silently turn the endpoint off, which does not
	// break a test, it makes it vacuous.
	MCPDisabled bool
	// ConsoleDebug opens the detection-catalogue editor in the console and the two
	// routes that write a catalogue. Set MILVAGO_DEBUG to 1/true/on/yes.
	//
	// Named positively, unlike MCPDisabled, and for the same reasoning applied to the
	// opposite case: here the zero value has to mean "the editor is hidden and the
	// write routes are closed", so a hand-built Config -- the test fixtures included
	// -- lands on the closed behaviour rather than silently exposing the editor.
	//
	// It is a noise decision, not a security boundary: publishing still demands the
	// root-organization owner and a fresh MFA. Nothing reads this flag from a
	// request; only the environment sets it.
	ConsoleDebug bool
	// DemoReadOnly refuses every console mutation on this instance, whatever the
	// caller's role. Set MILVAGO_DEMO_READONLY to 1/true/on/yes.
	//
	// Named positively, like ConsoleDebug and for the same reason: the zero value
	// has to mean "the server behaves normally", so a hand-built Config -- every
	// test fixture included -- keeps its mutations rather than silently losing them.
	//
	// It exists for an unattended demonstration instance, where the visiting account
	// must not be able to change anything an later visitor would see. A read-only
	// role already withholds every `*.manage` permission, but two console routes are
	// registered with no permission at all (PUT /api/profile, PUT /api/settings
	// field-level gating), so the role alone is not the whole answer. The flag is a
	// second, coarser boundary, not a replacement for the role.
	//
	// Device ingestion (/v1, /v2, /v3) is deliberately out of scope: it is how the
	// demonstration data arrives, it is authenticated by a device credential no
	// visitor holds, and a public deployment keeps those paths off the edge.
	DemoReadOnly bool
	// DemoMCPKey is the MCP credential a demonstration instance publishes, read from
	// MILVAGO_DEMO_MCP_KEY. It is shown on the profile page — and nowhere else — and
	// only while DemoReadOnly is set: an instance that accepts writes can mint its own
	// keys, so it has no reason to display one, and a customer instance must never
	// display a credential it did not just create.
	//
	// The server does not authenticate with it: the key lives hashed in api_keys like
	// any other. This field is the plaintext the operator chose to hand out, kept for
	// display, which is why it is inert everywhere else in the code.
	DemoMCPKey string
	// SHA-256 of MILVAGO_SETUP_TOKEN, the one-time secret that opens the first-run
	// setup wizard. Empty when unset, which keeps the wizard closed.
	SetupTokenHash []byte
}

func LoadConfig() (Config, error) {
	c := Config{DatabaseURL: os.Getenv("DATABASE_URL"), MigrationURL: os.Getenv("MIGRATION_DATABASE_URL"), RuntimeRole: env("DB_RUNTIME_ROLE", "milvago_runtime"), AppURL: strings.TrimRight(os.Getenv("APP_URL"), "/"), Issuer: strings.TrimRight(os.Getenv("OIDC_ISSUER"), "/"), InternalOIDC: strings.TrimRight(os.Getenv("OIDC_INTERNAL_URL"), "/"), ClientID: os.Getenv("OIDC_CLIENT_ID"), ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"), BootstrapEmail: strings.ToLower(strings.TrimSpace(os.Getenv("BOOTSTRAP_EMAIL"))), OrganizationName: env("COMMUNITY_ORG_NAME", "Milvago"), StaticDir: env("STATIC_DIR", "../console/dist"), Listen: env("LISTEN_ADDR", ":4020")}
	c.Role = env("MILVAGO_ROLE", RoleAll)
	if e := validateProcessRole(c.Role); e != nil {
		return c, e
	}
	c.PublisherURL = strings.TrimRight(os.Getenv("MILVAGO_PUBLISHER_URL"), "/")
	c.PublisherCredential = os.Getenv("MILVAGO_PUBLISHER_CREDENTIAL")
	if raw := os.Getenv("MILVAGO_PUBLISHER_PUBLIC_KEY"); raw != "" {
		key, e := base64.StdEncoding.DecodeString(raw)
		if e != nil || len(key) != ed25519.PublicKeySize {
			return c, errors.New("MILVAGO_PUBLISHER_PUBLIC_KEY must encode 32 bytes")
		}
		c.PublisherPublicKey = ed25519.PublicKey(key)
	}
	if c.PublisherURL != "" {
		if _, e := publisherOrigin(c.PublisherURL); e != nil {
			return c, e
		}
		if len(c.PublisherCredential) < 32 || len(c.PublisherPublicKey) != ed25519.PublicKeySize {
			return c, errors.New("publisher requires credentials and a pinned public key")
		}
	}
	c.MetricsToken = os.Getenv("MILVAGO_METRICS_TOKEN")
	c.ShadowMetrics = !slices.Contains([]string{"0", "false", "off", "no"}, strings.ToLower(strings.TrimSpace(os.Getenv("MILVAGO_SHADOW_METRICS"))))
	c.MCPDisabled = slices.Contains([]string{"0", "false", "off", "no"}, strings.ToLower(strings.TrimSpace(os.Getenv("MILVAGO_MCP"))))
	c.ConsoleDebug = slices.Contains([]string{"1", "true", "on", "yes"}, strings.ToLower(strings.TrimSpace(os.Getenv("MILVAGO_DEBUG"))))
	c.DemoReadOnly = slices.Contains([]string{"1", "true", "on", "yes"}, strings.ToLower(strings.TrimSpace(os.Getenv("MILVAGO_DEMO_READONLY"))))
	// Only kept when the instance is read-only: a value left in the environment of an
	// instance that later accepts writes must not become a displayed credential.
	if c.DemoReadOnly {
		c.DemoMCPKey = strings.TrimSpace(os.Getenv("MILVAGO_DEMO_MCP_KEY"))
	}
	if raw := os.Getenv("MILVAGO_OTEL_HTTP_HOSTS"); raw != "" {
		for _, host := range strings.Split(raw, ",") {
			host = strings.TrimSpace(host)
			u, err := url.Parse("http://" + host)
			if err != nil || u.Host != host || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(host, " \t\r\n") {
				return c, errors.New("invalid MILVAGO_OTEL_HTTP_HOSTS entry")
			}
			c.OTelHTTPHosts = append(c.OTelHTTPHosts, host)
		}
	}
	c.AdminClientID = os.Getenv("OIDC_ADMIN_CLIENT_ID")
	// Only the digest is kept: the plaintext setup token never outlives this function.
	if raw := os.Getenv("MILVAGO_SETUP_TOKEN"); raw != "" {
		if len(raw) < 32 {
			return c, errors.New("MILVAGO_SETUP_TOKEN must contain at least 32 characters")
		}
		c.SetupTokenHash = hash(raw)
	}
	c.AdminClientSecret = os.Getenv("OIDC_ADMIN_CLIENT_SECRET")
	if env("EDITION", Edition) != Edition {
		return c, errors.New("EDITION does not match the compiled server composition")
	}
	required := map[string]string{"DATABASE_URL": c.DatabaseURL}
	if c.ServesAPI() {
		required["APP_URL"], required["OIDC_ISSUER"] = c.AppURL, c.Issuer
		required["OIDC_CLIENT_ID"], required["OIDC_CLIENT_SECRET"] = c.ClientID, c.ClientSecret
	}
	if c.RunsMigrations() {
		// BOOTSTRAP_EMAIL is optional: without it the first administrator is created
		// through the setup wizard (setup.go) instead of a pre-imported account.
		required["MIGRATION_DATABASE_URL"] = c.MigrationURL
		required["APP_URL"] = c.AppURL
	}
	if c.ProcessRole() == RoleMaintenance || (c.ProcessRole() == RoleMigrate && Edition == "commercial" && !c.MCPDisabled) {
		required["OIDC_ISSUER"] = c.Issuer
	}
	for n, v := range required {
		if v == "" {
			return c, fmt.Errorf("%s is required", n)
		}
	}
	u, e := url.Parse(c.AppURL)
	if c.AppURL != "" && (e != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || !secureURL(u)) {
		return c, errors.New("APP_URL must be an HTTPS origin (HTTP permitted only on explicit loopback)")
	}
	c.SecureCookies = u.Scheme == "https"
	c.PublicURL = strings.TrimRight(os.Getenv("PUBLIC_URL"), "/")
	if c.PublicURL == "" {
		c.PublicURL = c.AppURL
	}
	if c.PublicURL != "" && !validOrigin(c.PublicURL) {
		return c, errors.New("PUBLIC_URL must be an HTTPS origin (HTTP permitted only on explicit loopback)")
	}
	u, e = url.Parse(c.Issuer)
	if c.Issuer != "" && (e != nil || u.Host == "" || u.User != nil || !secureURL(u)) {
		return c, errors.New("OIDC_ISSUER must use HTTPS or explicit loopback")
	}
	if !regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`).MatchString(c.RuntimeRole) {
		return c, errors.New("invalid DB_RUNTIME_ROLE")
	}
	var key []byte
	if c.ServesAPI() || os.Getenv("SESSION_KEY") != "" {
		key, e = decodeKey("SESSION_KEY")
		if e != nil {
			return c, e
		}
		if c.ServesAPI() {
			b, e := aes.NewCipher(key)
			if e != nil {
				return c, e
			}
			c.SessionCipher, e = cipher.NewGCM(b)
			if e != nil {
				return c, e
			}
		}
	}
	c.ContentKeys, c.ContentVersion, e = decodeContentKeys(key)
	if e != nil {
		return c, e
	}
	if c.ServesAPI() {
		seed, e := decodeKey("POLICY_SIGNING_KEY")
		if e != nil {
			return c, e
		}
		// One secret for two jobs: a leaked session key would also forge signed
		// policies, as the content-key check below refuses for content.
		if len(key) > 0 && subtle.ConstantTimeCompare(seed, key) == 1 {
			return c, errors.New("POLICY_SIGNING_KEY must differ from SESSION_KEY")
		}
		c.SigningKey = ed25519.NewKeyFromSeed(seed)
	}
	// Updates are served from MILVAGO_INSTALLER_DIRECTORY, next to the installers the
	// console hands out; only the verification key is configured separately.
	if raw := os.Getenv("MILVAGO_UPDATE_PUBLIC_KEY"); raw != "" {
		key, e := base64.StdEncoding.DecodeString(raw)
		if e != nil || len(key) != ed25519.PublicKeySize {
			return c, errors.New("MILVAGO_UPDATE_PUBLIC_KEY must encode 32 bytes")
		}
		c.UpdatePublicKey = ed25519.PublicKey(key)
	}
	if path := os.Getenv("MILVAGO_EXPORT_CA_FILE"); path != "" {
		pem, e := os.ReadFile(path)
		if e != nil || len(pem) > 1024*1024 {
			return c, errors.New("export CA file is unreadable or oversized")
		}
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return c, errors.New("export CA file contains no usable certificates")
		}
		c.CollectorRoots = roots
	}
	return c, nil
}
func secureURL(u *url.URL) bool {
	return u.Scheme == "https" || (u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))
}

// validOrigin reports whether raw is a bare HTTPS origin (or explicit loopback
// HTTP): scheme + host only, no path, query, fragment or userinfo. Used for both
// the APP_URL/PUBLIC_URL env values and the admin-editable public_url setting.
func validOrigin(raw string) bool {
	// Reject any query/fragment/whitespace/control byte outright (covers CRLF
	// header/log injection and the "https://x?" / "https://x#" edge cases that
	// url.Parse otherwise tolerates), then require a bare origin.
	if strings.ContainsAny(raw, "?# \t\r\n") {
		return false
	}
	u, e := url.Parse(raw)
	return e == nil && u.Opaque == "" && u.Host != "" && u.Path == "" && u.RawQuery == "" &&
		!u.ForceQuery && u.Fragment == "" && u.User == nil && secureURL(u)
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func decodeKey(n string) ([]byte, error) {
	b, e := base64.StdEncoding.DecodeString(os.Getenv(n))
	if e != nil || len(b) != 32 {
		return nil, fmt.Errorf("%s must be standard base64 encoding of 32 bytes", n)
	}
	return b, nil
}

// decodeContentKeys reads CONTENT_KEYS, the content-encryption roots, written as
// "version:base64,version:base64". The highest version present is the one new
// ciphertext is sealed with; the lower ones stay only to open what has not been
// re-sealed yet, and are removed once nothing needs them. Rotation is therefore
// appending a higher version, never replacing the only one there is.
//
// One variable rather than a list plus a separate "active version" pointer: two
// variables can disagree, and a disagreement here is either a database that
// cannot be read or -- worse, because nothing complains -- content sealed under a
// key the operator believed retired.
func decodeContentKeys(session []byte) (map[int][]byte, int, error) {
	raw := strings.TrimSpace(os.Getenv("CONTENT_KEYS"))
	if raw == "" {
		return nil, 0, errors.New(`CONTENT_KEYS must list at least one version, as "1:<standard base64 of 32 bytes>"`)
	}
	keys := map[int][]byte{}
	active := 0
	for _, entry := range strings.Split(raw, ",") {
		label, encoded, found := strings.Cut(strings.TrimSpace(entry), ":")
		if !found {
			return nil, 0, errors.New(`each CONTENT_KEYS entry must be "<version>:<standard base64 of 32 bytes>"`)
		}
		version, e := strconv.Atoi(label)
		if e != nil || version < 1 {
			return nil, 0, errors.New("CONTENT_KEYS versions must be positive integers")
		}
		if _, seen := keys[version]; seen {
			return nil, 0, fmt.Errorf("CONTENT_KEYS declares version %d twice", version)
		}
		key, e := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		if e != nil || len(key) != 32 {
			return nil, 0, fmt.Errorf("CONTENT_KEYS version %d must encode 32 bytes", version)
		}
		// A content key equal to the session key rebuilds by hand the very
		// conflation this separation removes, and does it silently: everything
		// keeps working until the day SESSION_KEY is rotated and every sealed
		// prompt and deployment key becomes unreadable.
		if subtle.ConstantTimeCompare(key, session) == 1 {
			return nil, 0, fmt.Errorf("CONTENT_KEYS version %d must differ from SESSION_KEY", version)
		}
		keys[version] = key
		active = max(active, version)
	}
	return keys, active, nil
}
