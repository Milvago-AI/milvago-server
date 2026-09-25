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
	if err := d.validateConnection(); err != nil {
		return err
	}
	if err := d.validateAuthentication(); err != nil {
		return err
	}
	return d.validateSchema()
}

func (d *directoryConfig) validateConnection() error {
	if len(d.ConnectionURL) > 300 || strings.ContainsAny(d.ConnectionURL, " \t\r\n") {
		return bad("Connection URL is too long or malformed.")
	}
	u, err := url.Parse(d.ConnectionURL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Opaque != "" || u.Host == "" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return bad("Connection URL must be ldap://host[:port] or ldaps://host[:port].")
	}
	if err := d.canonicalizeConnectionHost(u); err != nil {
		return err
	}
	if u.Scheme != "ldaps" && !d.StartTLS {
		return bad("LDAP requires LDAPS or StartTLS before any directory credentials are transmitted.")
	}
	if d.StartTLS && u.Scheme == "ldaps" {
		return bad("StartTLS cannot be combined with ldaps.")
	}
	return nil
}

func (d *directoryConfig) canonicalizeConnectionHost(u *url.URL) error {
	// Only a DNS name or an IP literal, with a real port, reaches Keycloak's
	// LDAP client; the URL is stored in canonical form.
	host, port := u.Hostname(), u.Port()
	if !ldapHostPattern.MatchString(host) && net.ParseIP(host) == nil {
		return bad("Connection URL host must be a DNS name or an IP address.")
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return bad("Connection URL port must be between 1 and 65535.")
		}
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	d.ConnectionURL = u.Scheme + "://" + host
	return nil
}

func (d *directoryConfig) validateAuthentication() error {
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
	return nil
}

func (d *directoryConfig) validateSchema() error {
	for _, attr := range []string{d.UsernameAttribute, d.RDNAttribute, d.UUIDAttribute} {
		if !ldapNamePattern.MatchString(attr) {
			return bad("LDAP attribute names must be alphanumeric.")
		}
	}
	if err := d.validateObjectClasses(); err != nil {
		return err
	}
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

func (d *directoryConfig) validateObjectClasses() error {
	if len(d.UserObjectClasses) > 256 {
		return bad("User object classes must contain at most 256 characters.")
	}
	var classes []string
	for _, class := range strings.Split(d.UserObjectClasses, ",") {
		class = strings.TrimSpace(class)
		if !ldapNamePattern.MatchString(class) {
			return bad("User object classes must be a comma-separated list of names.")
		}
		classes = append(classes, class)
	}
	d.UserObjectClasses = strings.Join(classes, ", ")
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
func alignNameMapper(ctx context.Context, admin *identityAdmin, component string) {
	status, _, raw, e := admin.call(ctx, "GET", "/components?parent="+url.QueryEscape(component)+"&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper", nil)
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
			_, _, _, _ = admin.call(ctx, "PUT", ldapComponentPath+url.PathEscape(id), m)
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

func (a *App) readDirectoryAdminBody(w http.ResponseWriter, r *http.Request, tx pgx.Tx, session *Session) (directoryBody, error) {
	if err := requireDirectoryOperator(r.Context(), tx, session); err != nil {
		return directoryBody{}, err
	}
	var body directoryBody
	if err := decode(w, r, &body); err != nil {
		return directoryBody{}, err
	}
	if err := body.validate(); err != nil {
		return directoryBody{}, err
	}
	if hasControl(body.BindCredential) || len(body.BindCredential) > 512 {
		return directoryBody{}, bad("Bind password is too long or malformed.")
	}
	// Both operations can use a stored bind credential.
	if err := a.requireFreshMFA(r, tx, session); err != nil {
		return directoryBody{}, err
	}
	return body, nil
}

func (a *App) putDirectory(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	body, err := a.readDirectoryAdminBody(w, r, tx, s)
	if err != nil {
		return err
	}
	admin, err := a.identityAdmin(r.Context())
	if err != nil {
		return err
	}
	// Serialize directory changes per organization.
	if _, err := tx.Exec(r.Context(), "SELECT id FROM organizations WHERE id=$1 FOR UPDATE", s.OrganizationID); err != nil {
		return err
	}
	stored, component, err := loadDirectory(r.Context(), tx, s.OrganizationID)
	create := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !create {
		return err
	}
	credential, err := directoryBindCredential(body, stored, create)
	if err != nil {
		return err
	}
	current, create, err := readDirectoryComponent(r.Context(), admin, component, create, credential)
	if err != nil {
		return err
	}
	component, err = writeDirectoryComponent(r.Context(), admin, body, credential, component, create, current)
	if err != nil {
		return err
	}
	alignNameMapper(r.Context(), admin, component)
	view, err := persistDirectoryUpdate(r.Context(), tx, s, admin, component, body, create)
	if err != nil {
		return err
	}
	reply(w, 200, view)
	return nil
}

func directoryBindCredential(body directoryBody, stored directoryView, create bool) (string, error) {
	credential := body.BindCredential
	switch {
	case body.AuthType == "none":
		credential = ""
	case credential == "" && create:
		return "", bad("A bind password is required to create the directory.")
	case credential == "":
		// Reusing the stored secret for another server would disclose it.
		if body.ConnectionURL != stored.ConnectionURL {
			return "", bad("The bind password must be entered again to change the directory server.")
		}
		credential = secretMask // Keycloak keeps the stored secret
	}
	return credential, nil
}

func readDirectoryComponent(ctx context.Context, admin *identityAdmin, component string, create bool, credential string) (map[string]any, bool, error) {
	if create {
		return nil, true, nil
	}
	status, _, raw, err := admin.call(ctx, "GET", ldapComponentPath+url.PathEscape(component), nil)
	if err != nil {
		return nil, false, err
	}
	var current map[string]any
	switch status {
	case 200:
		if json.Unmarshal(raw, &current) != nil {
			return nil, false, apiError{502, "identity_unavailable", "Invalid identity administration response."}
		}
	case 404:
		// The component vanished on the Keycloak side: recreate it.
		if credential == secretMask {
			return nil, false, bad("The directory no longer exists in the identity provider; provide the bind password again.")
		}
		return nil, true, nil
	default:
		return nil, false, apiError{502, "identity_unavailable", "Could not read the directory in the identity provider."}
	}
	return current, false, nil
}

func writeDirectoryComponent(ctx context.Context, admin *identityAdmin, body directoryBody, credential, component string, create bool, current map[string]any) (string, error) {
	config := body.componentConfig(credential)
	if create {
		status, header, _, err := admin.call(ctx, "POST", "/components", map[string]any{"name": body.Name, "providerId": "ldap", "providerType": "org.keycloak.storage.UserStorageProvider", "config": config})
		if err != nil {
			return "", err
		}
		if status != 201 {
			return "", apiError{502, "identity_unavailable", "The identity provider refused the directory configuration."}
		}
		component = path.Base(header.Get("Location"))
		if component == "" || component == "." || component == "/" || !ldapSubjectPattern.MatchString(component) {
			return "", apiError{502, "identity_unavailable", "The identity provider did not return the directory identifier."}
		}
		return component, nil
	}
	current["name"] = body.Name
	current["config"] = config
	status, _, _, err := admin.call(ctx, "PUT", ldapComponentPath+url.PathEscape(component), current)
	if err != nil {
		return "", err
	}
	if status != 204 {
		return "", apiError{502, "identity_unavailable", "The identity provider refused the directory configuration."}
	}
	return component, nil
}

func persistDirectoryUpdate(ctx context.Context, tx pgx.Tx, s *Session, admin *identityAdmin, component string, body directoryBody, create bool) (directoryView, error) {
	if err := saveDirectory(ctx, tx, s.OrganizationID, component, body.directoryConfig); err != nil {
		if create {
			// Best effort: do not leave an unreferenced provider behind.
			_, _, _, _ = admin.call(ctx, "DELETE", ldapComponentPath+url.PathEscape(component), nil)
		}
		return directoryView{}, err
	}
	if err := audit(ctx, tx, s.OrganizationID, s.UserID, "directory.update", s.OrganizationID); err != nil {
		return directoryView{}, err
	}
	view, _, err := loadDirectory(ctx, tx, s.OrganizationID)
	if err != nil {
		return directoryView{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return directoryView{}, err
	}
	return view, nil
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
	status, _, _, e := admin.call(r.Context(), "DELETE", ldapComponentPath+url.PathEscape(component), nil)
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
	body, err := a.readDirectoryAdminBody(w, r, tx, s)
	if err != nil {
		return err
	}
	credential, component, err := directoryTestCredential(r.Context(), tx, s.OrganizationID, body)
	if err != nil {
		return err
	}
	admin, err := a.identityAdmin(r.Context())
	if err != nil {
		return err
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
		ok, message, err := runDirectoryConnectionTest(r.Context(), admin, body, credential, component, action)
		if err != nil {
			return err
		}
		if !ok {
			reply(w, 200, map[string]any{"ok": false, "step": step, "message": message})
			return nil
		}
	}
	reply(w, 200, map[string]any{"ok": true, "step": steps[len(steps)-1]})
	return nil
}

func directoryTestCredential(ctx context.Context, tx pgx.Tx, org string, body directoryBody) (string, string, error) {
	credential, component := body.BindCredential, ""
	if body.AuthType == "none" {
		credential = ""
	} else if credential == "" {
		// Reuse the secret only for the server it was saved against.
		stored, id, err := loadDirectory(ctx, tx, org)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", bad("A bind password is required to test the connection.")
		}
		if err != nil {
			return "", "", err
		}
		if body.ConnectionURL != stored.ConnectionURL {
			return "", "", bad("The bind password must be entered again to change the directory server.")
		}
		credential, component = secretMask, id
	}
	return credential, component, nil
}

func runDirectoryConnectionTest(ctx context.Context, admin *identityAdmin, body directoryBody, credential, component, action string) (bool, string, error) {
	status, _, raw, err := admin.call(ctx, "POST", "/testLDAPConnection", map[string]string{"action": action, "connectionUrl": body.ConnectionURL, "bindDn": body.BindDN, "bindCredential": credential, "useTruststoreSpi": body.UseTruststore, "connectionTimeout": strconv.Itoa(body.ConnectionTimeout), "startTls": strconv.FormatBool(body.StartTLS), "authType": body.AuthType, "componentId": component})
	if err != nil {
		return false, "", err
	}
	if status == 204 {
		return true, "", nil
	}
	if status >= 500 {
		return false, "", apiError{502, "identity_unavailable", "The identity provider could not run the directory test."}
	}
	return false, keycloakMessage(raw), nil
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
	if directory.validate() != nil {
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
	found, err := searchDirectoryUsers(r.Context(), admin, query, component)
	if err != nil {
		return err
	}
	members, err := directoryMemberSet(r.Context(), tx, found, component)
	if err != nil {
		return err
	}
	items := directorySearchItems(found, component, members)
	reply(w, 200, map[string]any{"items": items})
	return nil
}

func searchDirectoryUsers(ctx context.Context, admin *identityAdmin, query, component string) ([]identityUser, error) {
	// Keycloak searches every provider, so filter each page by this organization's component.
	found := []identityUser{}
	const pageSize, searchLimit = 100, 1000
	for first := 0; ; first += pageSize {
		status, _, raw, err := admin.call(ctx, "GET", "/users?search="+url.QueryEscape(query)+"&first="+strconv.Itoa(first)+"&max="+strconv.Itoa(pageSize), nil)
		if err != nil {
			return nil, err
		}
		var page []identityUser
		if status != 200 || json.Unmarshal(raw, &page) != nil || len(page) > pageSize {
			return nil, apiError{502, "identity_unavailable", "Could not search the directory."}
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
			return nil, apiError{422, "search_too_broad", "This search matches too many accounts. Use a more specific name or email."}
		}
	}
	return found, nil
}

func directoryMemberSet(ctx context.Context, tx pgx.Tx, found []identityUser, component string) (map[string]bool, error) {
	var subjects []string
	for _, user := range found {
		if user.FederationLink == component {
			subjects = append(subjects, user.ID)
		}
	}
	members := map[string]bool{}
	if len(subjects) == 0 {
		return members, nil
	}
	rows, err := tx.Query(ctx, "SELECT u.subject FROM memberships m JOIN users u ON u.id=m.user_id WHERE u.subject=ANY($1)", subjects)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var subject string
		if err := rows.Scan(&subject); err != nil {
			return nil, err
		}
		members[subject] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return members, nil
}

func directorySearchItems(found []identityUser, component string, members map[string]bool) []map[string]string {
	items := []map[string]string{}
	for _, user := range found {
		if user.FederationLink != component || members[user.ID] {
			continue
		}
		items = append(items, map[string]string{"subject": user.ID, "username": user.Username, "email": strings.ToLower(user.Email), "display_name": user.displayName()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i]["username"] < items[j]["username"] })
	return items
}

func validateDirectoryImportRole(ctx context.Context, tx pgx.Tx, s *Session, role string) error {
	if role == "owner" && s.Role != "owner" {
		return forbidden()
	}
	// A key cannot import a directory account into a role broader than itself.
	if may, err := mayGrantRole(ctx, tx, s, role); err != nil {
		return err
	} else if !may {
		return notGranted()
	}
	var known bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM roles WHERE name=$1)", role).Scan(&known); err != nil {
		return err
	}
	if !known {
		return bad("Unknown role for this organization.")
	}
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
	if err := validateDirectoryImportRole(r.Context(), tx, s, body.Role); err != nil {
		return err
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
	u, e := admin.user(r.Context(), body.Subject)
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
