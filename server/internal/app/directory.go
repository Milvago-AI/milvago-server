package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
)

// Per-organization LDAP directory, materialized in Keycloak as a user-storage
// component (providerId "ldap"). The organization row keeps the connection
// settings for display; the bind credential lives in Keycloak only.

type directoryConfig struct {
	Name              string `json:"name"`
	Vendor            string `json:"vendor"`
	ConnectionURL     string `json:"connection_url"`
	BindDN            string `json:"bind_dn"`
	UsersDN           string `json:"users_dn"`
	UsernameAttribute string `json:"username_attribute"`
	RDNAttribute      string `json:"rdn_attribute"`
	UUIDAttribute     string `json:"uuid_attribute"`
	UserObjectClasses string `json:"user_object_classes"`
	CustomFilter      string `json:"custom_filter"`
	SearchScope       int    `json:"search_scope"`
	AuthType          string `json:"auth_type"`
	StartTLS          bool   `json:"start_tls"`
	UseTruststore     string `json:"use_truststore"`
	ConnectionTimeout int    `json:"connection_timeout_ms"`
	ReadTimeout       int    `json:"read_timeout_ms"`
	Pagination        bool   `json:"pagination"`
}

type directoryBody struct {
	directoryConfig
	BindCredential string `json:"bind_credential"`
}

type directoryView struct {
	Configured bool `json:"configured"`
	// Editable: the caller may change it (see directoryOperator).
	Editable bool `json:"editable"`
	directoryConfig
	UpdatedAt time.Time `json:"updated_at"`
}

// secretMask is Keycloak's placeholder for "keep the stored secret".
const secretMask = "**********"

const (
	ldapComponentPath         = "/components/"
	msgDirectoryNotConfigured = "No LDAP directory is configured for this organization."
)

var (
	ldapNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)
	// DNS name of the directory host (IP literals are checked with net.ParseIP).
	ldapHostPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$`)
	// Keycloak account IDs (UUID or f:<component>:<external>); the leading
	// alphanumeric rules out dot segments that would alter the admin API path.
	ldapSubjectPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}$`)
	ldapVendors        = map[string]bool{"ad": true, "rhds": true, "tivoli": true, "edirectory": true, "other": true}
	directoryColumns   = "name,vendor,connection_url,bind_dn,users_dn,username_attribute,rdn_attribute,uuid_attribute,user_object_classes,custom_filter,search_scope,auth_type,start_tls,use_truststore,connection_timeout_ms,read_timeout_ms,pagination"
)

func (a *App) registerDirectoryRoutes() {
	a.console("GET /api/settings/ldap", permDirectoryManage, a.directory)
	// Fresh second factor on all three, so session-only on the registration line (an API
	// key cannot present one): deleting removes every account imported from the directory.
	// No directory without a licence in Community (license.go); removing one stays
	// possible.
	a.sessionOnly("PUT /api/settings/ldap", permDirectoryManage, a.licensed(a.putDirectory))
	a.sessionOnly("DELETE /api/settings/ldap", permDirectoryManage, a.deleteDirectory)
	a.sessionOnly("POST /api/settings/ldap/test", permDirectoryManage, a.licensed(a.testDirectory))
	a.console("GET /api/members/directory", permMembersManage, a.licensed(a.searchDirectory))
	a.console("POST /api/members/directory", permMembersManage, a.licensed(a.importDirectoryMember))
}

func hasControl(v string) bool {
	for _, r := range v {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// validate normalizes and bounds a submitted configuration before any value
// reaches Keycloak or the database.
func (d *directoryConfig) validate() error {
	d.Name = strings.TrimSpace(d.Name)
	d.ConnectionURL = strings.TrimSpace(d.ConnectionURL)
	d.BindDN = strings.TrimSpace(d.BindDN)
	d.UsersDN = strings.TrimSpace(d.UsersDN)
	d.CustomFilter = strings.TrimSpace(d.CustomFilter)
	for _, v := range []string{d.Name, d.ConnectionURL, d.BindDN, d.UsersDN, d.CustomFilter, d.UserObjectClasses} {
		if hasControl(v) {
			return bad("Directory settings must not contain control characters.")
		}
	}
	if len(d.Name) < 1 || len(d.Name) > 120 {
		return bad("Directory name must contain 1 to 120 characters.")
	}
	if !ldapVendors[d.Vendor] {
		return bad("Unknown directory vendor.")
	}
	if len(d.ConnectionURL) > 300 || strings.ContainsAny(d.ConnectionURL, " \t\r\n") {
		return bad("Connection URL is too long or malformed.")
	}
	u, e := url.Parse(d.ConnectionURL)
	if e != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Opaque != "" || u.Host == "" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return bad("Connection URL must be ldap://host[:port] or ldaps://host[:port].")
	}
	// Only a DNS name or an IP literal, with a real port, reaches Keycloak's
	// LDAP client; the URL is stored in canonical form.
	host, port := u.Hostname(), u.Port()
	if !ldapHostPattern.MatchString(host) && net.ParseIP(host) == nil {
		return bad("Connection URL host must be a DNS name or an IP address.")
	}
	if port != "" {
		if n, e := strconv.Atoi(port); e != nil || n < 1 || n > 65535 {
			return bad("Connection URL port must be between 1 and 65535.")
		}
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	d.ConnectionURL = u.Scheme + "://" + host
	if u.Scheme != "ldaps" && !d.StartTLS {
		return bad("LDAP requires LDAPS or StartTLS before any directory credentials are transmitted.")
	}
	if d.StartTLS && u.Scheme == "ldaps" {
		return bad("StartTLS cannot be combined with ldaps.")
	}
	switch d.AuthType {
	case "none":
		d.BindDN = ""
	case "simple":
		if d.BindDN == "" {
			return bad("A bind DN is required for simple authentication.")
		}
	default:
		return bad("Authentication type must be simple or none.")
	}
	if len(d.BindDN) > 512 {
		return bad("Bind DN must contain at most 512 characters.")
	}
	if len(d.UsersDN) < 1 || len(d.UsersDN) > 512 {
		return bad("Users DN must contain 1 to 512 characters.")
	}
	for _, attr := range []string{d.UsernameAttribute, d.RDNAttribute, d.UUIDAttribute} {
		if !ldapNamePattern.MatchString(attr) {
			return bad("LDAP attribute names must be alphanumeric.")
		}
	}
	if len(d.UserObjectClasses) > 256 {
		return bad("User object classes must contain at most 256 characters.")
	}
	var classes []string
	for _, c := range strings.Split(d.UserObjectClasses, ",") {
		c = strings.TrimSpace(c)
		if !ldapNamePattern.MatchString(c) {
			return bad("User object classes must be a comma-separated list of names.")
		}
		classes = append(classes, c)
	}
	d.UserObjectClasses = strings.Join(classes, ", ")
	if len(d.CustomFilter) > 1024 || (d.CustomFilter != "" && (!strings.HasPrefix(d.CustomFilter, "(") || !strings.HasSuffix(d.CustomFilter, ")"))) {
		return bad("Custom filter must be enclosed in parentheses and contain at most 1024 characters.")
	}
	if d.SearchScope != 1 && d.SearchScope != 2 {
		return bad("Search scope must be 1 (one level) or 2 (subtree).")
	}
	if d.UseTruststore != "always" {
		return bad("Directory TLS must use the configured truststore.")
	}
	if d.ConnectionTimeout < 0 || d.ConnectionTimeout > 300000 || d.ReadTimeout < 0 || d.ReadTimeout > 300000 {
		return bad("Timeouts must be between 0 and 300000 milliseconds.")
	}
	return nil
}

// componentConfig builds the Keycloak user-storage settings. Edit mode is
// forced read-only (the directory owns names, e-mails and passwords) and
// e-mails are trusted so federated users pass the verified-e-mail check.
func (d directoryConfig) componentConfig(credential string) map[string][]string {
	one := func(v string) []string { return []string{v} }
	flag := func(v bool) []string { return []string{strconv.FormatBool(v)} }
	millis := func(v int) []string {
		if v == 0 {
			return one("")
		}
		return one(strconv.Itoa(v))
	}
	return map[string][]string{
		"enabled": one("true"), "priority": one("0"), "editMode": one("READ_ONLY"), "importEnabled": one("true"), "syncRegistrations": one("false"),
		"trustEmail": one("true"), "removeInvalidUsersEnabled": one("true"), "cachePolicy": one("DEFAULT"), "batchSizeForSync": one("1000"),
		"fullSyncPeriod": one("-1"), "changedSyncPeriod": one("-1"), "connectionPooling": one("false"), "validatePasswordPolicy": one("false"),
		"allowKerberosAuthentication": one("false"), "usePasswordModifyExtendedOp": one("false"),
		"vendor": one(d.Vendor), "connectionUrl": one(d.ConnectionURL), "bindDn": one(d.BindDN), "bindCredential": one(credential), "usersDn": one(d.UsersDN),
		"usernameLDAPAttribute": one(d.UsernameAttribute), "rdnLDAPAttribute": one(d.RDNAttribute), "uuidLDAPAttribute": one(d.UUIDAttribute),
		"userObjectClasses": one(d.UserObjectClasses), "customUserSearchFilter": one(d.CustomFilter), "searchScope": one(strconv.Itoa(d.SearchScope)),
		"authType": one(d.AuthType), "startTls": flag(d.StartTLS), "useTruststoreSpi": one(d.UseTruststore),
		"connectionTimeout": millis(d.ConnectionTimeout), "readTimeout": millis(d.ReadTimeout), "pagination": flag(d.Pagination),
	}
}

// keycloakMessage extracts a short, printable error message from an admin
// API error body so the console can show why a directory test failed.
func keycloakMessage(raw []byte) string {
	var body struct {
		Message string `json:"errorMessage"`
		Error   string `json:"error"`
	}
	_ = json.Unmarshal(raw, &body)
	m := body.Message
	if m == "" {
		m = body.Error
	}
	m = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, m)
	if len(m) > 300 {
		m = m[:300]
	}
	return m
}

// alignNameMapper points Keycloak's default "first name" LDAP mapper at
// givenName. For non-AD vendors Keycloak defaults it to cn, which repeats the
// surname in every display name. Best effort: only display quality depends on it.
func alignNameMapper(admin *identityAdmin, component string) {
	status, _, raw, e := admin.call("GET", "/components?parent="+url.QueryEscape(component)+"&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper", nil)
	if e != nil || status != 200 {
		return
	}
	var mappers []map[string]any
	if json.Unmarshal(raw, &mappers) != nil {
		return
	}
	for _, m := range mappers {
		config, _ := m["config"].(map[string]any)
		model, _ := config["user.model.attribute"].([]any)
		id, _ := m["id"].(string)
		if len(model) == 1 && model[0] == "firstName" && id != "" {
			config["ldap.attribute"] = []string{"givenName"}
			_, _, _, _ = admin.call("PUT", ldapComponentPath+url.PathEscape(id), m)
		}
	}
}

func loadDirectory(ctx context.Context, tx pgx.Tx, org string) (directoryView, string, error) {
	var v directoryView
	var component string
	e := tx.QueryRow(ctx, `SELECT component_id,`+directoryColumns+`,updated_at FROM ldap_directories WHERE organization_id=$1`, org).Scan(&component, &v.Name, &v.Vendor, &v.ConnectionURL, &v.BindDN, &v.UsersDN, &v.UsernameAttribute, &v.RDNAttribute, &v.UUIDAttribute, &v.UserObjectClasses, &v.CustomFilter, &v.SearchScope, &v.AuthType, &v.StartTLS, &v.UseTruststore, &v.ConnectionTimeout, &v.ReadTimeout, &v.Pagination, &v.UpdatedAt)
	v.Configured = e == nil
	return v, component, e
}

func saveDirectory(ctx context.Context, tx pgx.Tx, org, component string, d directoryConfig) error {
	_, e := tx.Exec(ctx, `INSERT INTO ldap_directories(organization_id,component_id,`+directoryColumns+`) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
 ON CONFLICT(organization_id) DO UPDATE SET component_id=excluded.component_id,name=excluded.name,vendor=excluded.vendor,connection_url=excluded.connection_url,bind_dn=excluded.bind_dn,users_dn=excluded.users_dn,username_attribute=excluded.username_attribute,rdn_attribute=excluded.rdn_attribute,uuid_attribute=excluded.uuid_attribute,user_object_classes=excluded.user_object_classes,custom_filter=excluded.custom_filter,search_scope=excluded.search_scope,auth_type=excluded.auth_type,start_tls=excluded.start_tls,use_truststore=excluded.use_truststore,connection_timeout_ms=excluded.connection_timeout_ms,read_timeout_ms=excluded.read_timeout_ms,pagination=excluded.pagination,updated_at=now()`,
		org, component, d.Name, d.Vendor, d.ConnectionURL, d.BindDN, d.UsersDN, d.UsernameAttribute, d.RDNAttribute, d.UUIDAttribute, d.UserObjectClasses, d.CustomFilter, d.SearchScope, d.AuthType, d.StartTLS, d.UseTruststore, d.ConnectionTimeout, d.ReadTimeout, d.Pagination)
	return e
}

// directoryOperator reports whether the caller may create, change, test or delete a
// directory. In Enterprise the Keycloak realm is shared by every tenant, and Keycloak
// consults every LDAP component of it when anyone signs in with a name it has not
// imported yet: a tenant owner pointing a component at a server that answers yes to
// every name received other tenants' passwords in clear, and the connection test
// probed the operator's network (audit of 2026-09-24). A directory is therefore
// instance infrastructure there, configured by an owner of the root organization --
// for the root or, acting in it, for a child. Community has one organization.
func directoryOperator(ctx context.Context, tx pgx.Tx, s *Session) (bool, error) {
	if Edition != "commercial" {
		return true, nil
	}
	if s.pinned() {
		return false, nil
	}
	var operator bool
	e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM app_config c, effective_access($1,c.organization_id) e WHERE e.role='owner')`, s.UserID).Scan(&operator)
	return operator, e
}

func requireDirectoryOperator(ctx context.Context, tx pgx.Tx, s *Session) error {
	operator, e := directoryOperator(ctx, tx, s)
	if e != nil {
		return e
	}
	if !operator {
		return apiError{403, "operator_required", "Only an owner of the root organization can configure a directory: every organization's sign-in consults it."}
	}
	return nil
}

func (a *App) directory(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	editable, e := directoryOperator(r.Context(), tx, s)
	if e != nil {
		return e
	}
	view, _, e := loadDirectory(r.Context(), tx, s.OrganizationID)
	if errors.Is(e, pgx.ErrNoRows) {
		reply(w, 200, map[string]bool{"configured": false, "editable": editable})
		return nil
	}
	if e != nil {
		return e
	}
	view.Editable = editable
	reply(w, 200, view)
	return nil
}

func (a *App) putDirectory(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if e := requireDirectoryOperator(r.Context(), tx, s); e != nil {
		return e
	}
	var body directoryBody
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if e := body.validate(); e != nil {
		return e
	}
	if hasControl(body.BindCredential) || len(body.BindCredential) > 512 {
		return bad("Bind password is too long or malformed.")
	}
	// The stored bind credential answers this request, so it is a credential
	// operation: a recent second factor is required, and an API key — which
	// cannot present one — is refused here.
	if e := a.requireFreshMFA(r, tx, s); e != nil {
		return e
	}
	admin, e := a.identityAdmin(r.Context())
	if e != nil {
		return e
	}
	// Serialize directory changes per organization.
	if _, e := tx.Exec(r.Context(), `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, s.OrganizationID); e != nil {
		return e
	}
	stored, component, e := loadDirectory(r.Context(), tx, s.OrganizationID)
	create := errors.Is(e, pgx.ErrNoRows)
	if e != nil && !create {
		return e
	}
	credential := body.BindCredential
	switch {
	case body.AuthType == "none":
		credential = ""
	case credential == "" && create:
		return bad("A bind password is required to create the directory.")
	case credential == "":
		// The stored secret is reused only for the very server it was saved
		// against: keeping the old password while pointing the directory at a
		// new URL is how the credential would be handed to an attacker's host.
		// Both URLs are canonical (validate() normalizes the body in place, the
		// stored one was normalized when recorded), so equality is exact.
		if body.ConnectionURL != stored.ConnectionURL {
			return bad("The bind password must be entered again to change the directory server.")
		}
		credential = secretMask // Keycloak keeps the stored secret
	}
	var current map[string]any
	if !create {
		status, _, raw, e := admin.call("GET", ldapComponentPath+url.PathEscape(component), nil)
		if e != nil {
			return e
		}
		switch status {
		case 200:
			if json.Unmarshal(raw, &current) != nil {
				return apiError{502, "identity_unavailable", "Invalid identity administration response."}
			}
		case 404:
			// The component vanished on the Keycloak side: recreate it.
			create = true
			if credential == secretMask {
				return bad("The directory no longer exists in the identity provider; provide the bind password again.")
			}
		default:
			return apiError{502, "identity_unavailable", "Could not read the directory in the identity provider."}
		}
	}
	config := body.componentConfig(credential)
	if create {
		status, header, _, e := admin.call("POST", "/components", map[string]any{"name": body.Name, "providerId": "ldap", "providerType": "org.keycloak.storage.UserStorageProvider", "config": config})
		if e != nil {
			return e
		}
		if status != 201 {
			return apiError{502, "identity_unavailable", "The identity provider refused the directory configuration."}
		}
		component = path.Base(header.Get("Location"))
		if component == "" || component == "." || component == "/" || !ldapSubjectPattern.MatchString(component) {
			return apiError{502, "identity_unavailable", "The identity provider did not return the directory identifier."}
		}
	} else {
		current["name"] = body.Name
		current["config"] = config
		status, _, _, e := admin.call("PUT", ldapComponentPath+url.PathEscape(component), current)
		if e != nil {
			return e
		}
		if status != 204 {
			return apiError{502, "identity_unavailable", "The identity provider refused the directory configuration."}
		}
	}
	alignNameMapper(admin, component)
	if e := saveDirectory(r.Context(), tx, s.OrganizationID, component, body.directoryConfig); e != nil {
		if create {
			// Best effort: do not leave an unreferenced provider behind.
			_, _, _, _ = admin.call("DELETE", ldapComponentPath+url.PathEscape(component), nil)
		}
		return e
	}
	if e := audit(r.Context(), tx, s.OrganizationID, s.UserID, "directory.update", s.OrganizationID); e != nil {
		return e
	}
	view, _, e := loadDirectory(r.Context(), tx, s.OrganizationID)
	if e != nil {
		return e
	}
	if e := tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, view)
	return nil
}

func (a *App) deleteDirectory(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if e := requireDirectoryOperator(r.Context(), tx, s); e != nil {
		return e
	}
	if e := a.requireFreshMFA(r, tx, s); e != nil {
		return e
	}
	if _, e := tx.Exec(r.Context(), `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, s.OrganizationID); e != nil {
		return e
	}
	_, component, e := loadDirectory(r.Context(), tx, s.OrganizationID)
	if errors.Is(e, pgx.ErrNoRows) {
		return apiError{404, "directory_not_configured", msgDirectoryNotConfigured}
	}
	if e != nil {
		return e
	}
	admin, e := a.identityAdmin(r.Context())
	if e != nil {
		return e
	}
	status, _, _, e := admin.call("DELETE", ldapComponentPath+url.PathEscape(component), nil)
	if e != nil {
		return e
	}
	if status != 204 && status != 404 {
		return apiError{502, "identity_unavailable", "The identity provider could not remove the directory."}
	}
	if _, e := tx.Exec(r.Context(), `DELETE FROM ldap_directories WHERE organization_id=$1`, s.OrganizationID); e != nil {
		return e
	}
	if e := audit(r.Context(), tx, s.OrganizationID, s.UserID, "directory.remove", s.OrganizationID); e != nil {
		return e
	}
	if e := tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]bool{"ok": true})
	return nil
}

func (a *App) testDirectory(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if e := requireDirectoryOperator(r.Context(), tx, s); e != nil {
		return e
	}
	var body directoryBody
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if e := body.validate(); e != nil {
		return e
	}
	if hasControl(body.BindCredential) || len(body.BindCredential) > 512 {
		return bad("Bind password is too long or malformed.")
	}
	// Same standing as the save route: the test can spend the stored credential.
	if e := a.requireFreshMFA(r, tx, s); e != nil {
		return e
	}
	credential, component := body.BindCredential, ""
	if body.AuthType == "none" {
		credential = ""
	} else if credential == "" {
		// Reuse the secret Keycloak already holds for this organization's directory,
		// only against the server it was saved for (see putDirectory).
		stored, id, e := loadDirectory(r.Context(), tx, s.OrganizationID)
		if errors.Is(e, pgx.ErrNoRows) {
			return bad("A bind password is required to test the connection.")
		}
		if e != nil {
			return e
		}
		if body.ConnectionURL != stored.ConnectionURL {
			return bad("The bind password must be entered again to change the directory server.")
		}
		credential, component = secretMask, id
	}
	admin, e := a.identityAdmin(r.Context())
	if e != nil {
		return e
	}
	run := func(action string) (bool, string, error) {
		status, _, raw, e := admin.call("POST", "/testLDAPConnection", map[string]string{"action": action, "connectionUrl": body.ConnectionURL, "bindDn": body.BindDN, "bindCredential": credential, "useTruststoreSpi": body.UseTruststore, "connectionTimeout": strconv.Itoa(body.ConnectionTimeout), "startTls": strconv.FormatBool(body.StartTLS), "authType": body.AuthType, "componentId": component})
		if e != nil {
			return false, "", e
		}
		if status == 204 {
			return true, "", nil
		}
		if status >= 500 {
			return false, "", apiError{502, "identity_unavailable", "The identity provider could not run the directory test."}
		}
		return false, keycloakMessage(raw), nil
	}
	steps := []string{"connection"}
	if body.AuthType == "simple" {
		steps = append(steps, "authentication")
	}
	for _, step := range steps {
		action := "testConnection"
		if step == "authentication" {
			action = "testAuthentication"
		}
		ok, message, e := run(action)
		if e != nil {
			return e
		}
		if !ok {
			reply(w, 200, map[string]any{"ok": false, "step": step, "message": message})
			return nil
		}
	}
	reply(w, 200, map[string]any{"ok": true, "step": steps[len(steps)-1]})
	return nil
}

func (a *App) searchDirectory(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	directory, component, e := loadDirectory(r.Context(), tx, s.OrganizationID)
	if errors.Is(e, pgx.ErrNoRows) {
		return apiError{409, "directory_not_configured", msgDirectoryNotConfigured}
	}
	if e != nil {
		return e
	}
	if e := directory.validate(); e != nil {
		return apiError{409, "directory_transport_required", "Update this directory to verified LDAPS or StartTLS before searching."}
	}
	// Keycloak forwards the search text into LDAP filters: wildcards are
	// dropped and filter metacharacters are refused outright.
	query := strings.ReplaceAll(strings.TrimSpace(r.URL.Query().Get("query")), "*", "")
	if n := len([]rune(query)); n < 2 || n > 64 || hasControl(query) || strings.ContainsAny(query, `()\`) {
		return bad("Search text must contain 2 to 64 characters.")
	}
	admin, e := a.identityAdmin(r.Context())
	if e != nil {
		return e
	}
	// Keycloak searches every user-storage provider of the realm; only accounts
	// provided by this organization's own directory are kept.
	// Filter each page of realm accounts, not just its first twenty users.
	// An incomplete search is explicit rather than an empty success.
	found := []identityUser{}
	const pageSize, searchLimit = 100, 1000
	for first := 0; ; first += pageSize {
		status, _, raw, err := admin.call("GET", "/users?search="+url.QueryEscape(query)+"&first="+strconv.Itoa(first)+"&max="+strconv.Itoa(pageSize), nil)
		if err != nil {
			return err
		}
		var page []identityUser
		if status != 200 || json.Unmarshal(raw, &page) != nil || len(page) > pageSize {
			return apiError{502, "identity_unavailable", "Could not search the directory."}
		}
		for _, candidate := range page {
			if candidate.FederationLink == component {
				found = append(found, candidate)
			}
		}
		if len(page) < pageSize {
			break
		}
		if first+pageSize >= searchLimit {
			return apiError{422, "search_too_broad", "This search matches too many accounts. Use a more specific name or email."}
		}
	}
	var subjects []string
	for _, u := range found {
		if u.FederationLink == component {
			subjects = append(subjects, u.ID)
		}
	}
	members := map[string]bool{}
	if len(subjects) > 0 {
		rows, e := tx.Query(r.Context(), `SELECT u.subject FROM memberships m JOIN users u ON u.id=m.user_id WHERE u.subject=ANY($1)`, subjects)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var subject string
			if e = rows.Scan(&subject); e != nil {
				return e
			}
			members[subject] = true
		}
		if e = rows.Err(); e != nil {
			return e
		}
	}
	items := []map[string]string{}
	for _, u := range found {
		if u.FederationLink != component || members[u.ID] {
			continue
		}
		items = append(items, map[string]string{"subject": u.ID, "username": u.Username, "email": strings.ToLower(u.Email), "display_name": u.displayName()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i]["username"] < items[j]["username"] })
	reply(w, 200, map[string]any{"items": items})
	return nil
}

func (a *App) importDirectoryMember(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var body struct {
		Subject string `json:"subject"`
		Role    string `json:"role"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if !ldapSubjectPattern.MatchString(body.Subject) || body.Role == "" {
		return bad("Provide a directory account and a role.")
	}
	if body.Role == "owner" && s.Role != "owner" {
		return forbidden()
	}
	// A key cannot import a directory account into a role broader than itself.
	if may, e := mayGrantRole(r.Context(), tx, s, body.Role); e != nil {
		return e
	} else if !may {
		return notGranted()
	}
	var known bool
	if e := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM roles WHERE name=$1)`, body.Role).Scan(&known); e != nil {
		return e
	}
	if !known {
		return bad("Unknown role for this organization.")
	}
	_, component, e := loadDirectory(r.Context(), tx, s.OrganizationID)
	if errors.Is(e, pgx.ErrNoRows) {
		return apiError{409, "directory_not_configured", msgDirectoryNotConfigured}
	}
	if e != nil {
		return e
	}
	admin, e := a.identityAdmin(r.Context())
	if e != nil {
		return e
	}
	u, e := admin.user(body.Subject)
	if e != nil {
		return e
	}
	if u == nil {
		return apiError{404, "directory_user_not_found", "This account does not exist in the identity provider."}
	}
	// Authority comes from the organization's own directory: an account from
	// another provider (or a local one) is never importable here.
	if u.FederationLink == "" || u.FederationLink != component {
		return apiError{403, "forbidden", "This account is not provided by this organization's directory."}
	}
	email := strings.ToLower(strings.TrimSpace(u.Email))
	if email == "" {
		return apiError{400, "email_required", "This directory account has no e-mail address."}
	}
	if identityText(email) != email {
		return apiError{400, "invalid_email", "This directory account's e-mail address contains control characters."}
	}
	// Shared barrier for an addition: one account's additions serialize here.
	if e = lockAccount(r, tx, u.ID); e != nil {
		return e
	}
	var existing bool
	if e = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id WHERE u.subject=$1)`, u.ID).Scan(&existing); e != nil {
		return e
	}
	if existing {
		return apiError{409, "already_member", "This account is already a member."}
	}
	var user string
	if e = tx.QueryRow(r.Context(), `INSERT INTO users(subject,email,display_name,identity_type) VALUES($1,$2,$3,'ldap') ON CONFLICT(subject) DO UPDATE SET email=excluded.email,display_name=excluded.display_name,identity_type='ldap' RETURNING id`, u.ID, email, u.displayName()).Scan(&user); e != nil {
		return e
	}
	if e = guardParentControl(r.Context(), tx, s, user); e != nil {
		return e
	}
	if outside, e := outsideTree(r.Context(), tx, s.OrganizationID, user); e != nil {
		return e
	} else if outside {
		return apiError{409, "member_of_other_organization", "This account belongs to another organization. Invite it from an organization that contains both."}
	}
	if _, e = tx.Exec(r.Context(), `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3)`, s.OrganizationID, user, body.Role); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, "member.import", user); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 201, map[string]string{"id": user, "email": email, "role": body.Role, "identity_type": "ldap"})
	return nil
}
