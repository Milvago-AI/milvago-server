package app

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// First-run setup wizard. An instance started without BOOTSTRAP_EMAIL has no
// administrator yet. Whoever holds MILVAGO_SETUP_TOKEN -- provided by the operator,
// never logged, only its digest kept in memory -- opens a short setup session and
// chooses the first account, its security, the organization, the e-mail server and
// the privacy defaults. Nothing is written before the final step. The account is
// created in Keycloak, and the existing login bootstrap (auth.go) then makes it the
// owner: this file never grants a role itself. Once an administrator exists, every
// route here answers 404.

const (
	// Kept equal to the interval written in setupSession.
	setupSessionTTL = 30 * time.Minute
	// Serializes concurrent completions; distinct from the privacy barrier keys and
	// the observability lock (7069204), which it used to share.
	setupLockKey = 7069205
)

var errSetupClosed = apiError{404, "not_found", "Not found."}

func (a *App) registerSetupRoutes() {
	a.mux.HandleFunc("GET /api/setup", a.setupStatus)
	a.mux.HandleFunc("POST /api/setup/session", a.setupSession)
	a.mux.HandleFunc("POST /api/setup/smtp-test", a.setupSMTPTest)
	a.mux.HandleFunc("POST /api/setup/complete", a.setupComplete)
}

type rowQueryer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// setupPending is read from the database on every call, never cached: the answer
// changes once, for every replica at the same time.
func setupPending(ctx context.Context, q rowQueryer) (bool, error) {
	var pending bool
	e := q.QueryRow(ctx, `SELECT bootstrap_email='' AND NOT bootstrap_consumed FROM app_config`).Scan(&pending)
	return pending, e
}

// setupGate answers 404 before anything else once setup is over, so a finished
// instance reveals nothing about how it was configured.
func (a *App) setupGate(ctx context.Context) error {
	pending, e := setupPending(ctx, a.db)
	if e != nil {
		return e
	}
	if !pending {
		return errSetupClosed
	}
	if a.config.DemoReadOnly {
		return forbidden()
	}
	if len(a.config.SetupTokenHash) == 0 {
		return apiError{503, "setup_token_missing", "Set MILVAGO_SETUP_TOKEN to open the setup wizard."}
	}
	if a.config.AdminClientID == "" || a.config.AdminClientSecret == "" {
		return apiError{503, "identity_admin_unavailable", "Identity administration is not configured."}
	}
	return nil
}

func (a *App) setupStatus(w http.ResponseWriter, r *http.Request) {
	pending, e := setupPending(r.Context(), a.db)
	if e != nil {
		a.fail(w, e)
		return
	}
	out := map[string]any{"pending": pending, "ready": pending && a.setupGate(r.Context()) == nil, "edition": Edition}
	if pending {
		// The wizard starts from the server's own defaults rather than a copy of them.
		out["privacy_defaults"] = defaultPrivacy()
		// A licence is issued for this identifier (license.go).
		var instance string
		if e = a.db.QueryRow(r.Context(), `SELECT instance_id FROM publisher_client_state`).Scan(&instance); e != nil {
			a.fail(w, e)
			return
		}
		out["instance_id"] = instance
	}
	reply(w, 200, out)
}

func (a *App) setupOrigin(r *http.Request) error {
	if r.Header.Get("Origin") != a.config.AppURL {
		return forbidden()
	}
	return nil
}

func (a *App) setupSession(w http.ResponseWriter, r *http.Request) {
	if e := a.checkPublicRequest(r, "setup", 10, 60); e != nil {
		a.fail(w, e)
		return
	}
	if e := a.setupGate(r.Context()); e != nil {
		a.fail(w, e)
		return
	}
	if e := a.setupOrigin(r); e != nil {
		a.fail(w, e)
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if e := decode(w, r, &body); e != nil {
		a.fail(w, e)
		return
	}
	if subtle.ConstantTimeCompare(hash(body.Token), a.config.SetupTokenHash) != 1 {
		a.fail(w, apiError{403, "setup_token_invalid", "The setup token is not valid."})
		return
	}
	id, csrf := randomToken(), randomToken()
	if _, e := a.db.Exec(r.Context(), `INSERT INTO setup_sessions(id_hash,csrf,expires_at) VALUES($1,$2,now()+interval '30 minutes')`, hash(id), csrf); e != nil {
		a.fail(w, e)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName("setup"), Value: id, Path: "/api/setup", HttpOnly: true, Secure: a.config.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: int(setupSessionTTL.Seconds())})
	reply(w, 200, map[string]string{"csrf": csrf})
}

// setupAuth binds a mutation to a live setup session: its cookie, its own CSRF
// token and the application origin, the same three proofs as a console mutation.
func (a *App) setupAuth(r *http.Request) error {
	if e := a.setupOrigin(r); e != nil {
		return e
	}
	required := apiError{401, "setup_session_required", "Enter the setup token again."}
	cookie, e := r.Cookie(cookieName("setup"))
	if e != nil || cookie.Value == "" {
		return required
	}
	var csrf string
	e = a.db.QueryRow(r.Context(), `SELECT csrf FROM setup_sessions WHERE id_hash=$1 AND expires_at>now()`, hash(cookie.Value)).Scan(&csrf)
	if errors.Is(e, pgx.ErrNoRows) {
		return required
	}
	if e != nil {
		return e
	}
	if csrf == "" || !equal(r.Header.Get("X-CSRF-Token"), csrf) {
		return required
	}
	return nil
}

func (a *App) setupGuard(w http.ResponseWriter, r *http.Request, operation string) bool {
	for _, check := range []func() error{
		func() error { return a.checkPublicRequest(r, operation, 10, 60) },
		func() error { return a.setupGate(r.Context()) },
		func() error { return a.setupAuth(r) },
	} {
		if e := check(); e != nil {
			a.fail(w, e)
			return false
		}
	}
	return true
}

// setupSMTP is the mail server the realm will use for invitations.
type setupSMTP struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	From     string `json:"from"`
	FromName string `json:"from_name"`
	Security string `json:"security"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func validHostname(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) < 1 || len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, c := range host {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// plainAddress accepts a bare e-mail address only: no display name, no comment, and
// none of the characters the sign-in refuses in an e-mail (identityText): an owner
// address typed with an invisible direction mark could never sign in, and the
// wizard, once completed, would not reopen (audit of 2026-09-24).
func plainAddress(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	parsed, e := mail.ParseAddress(raw)
	if e != nil || parsed.Name != "" || parsed.Address != raw || len(raw) > 254 || identityText(raw) != raw {
		return "", false
	}
	return strings.ToLower(raw), true
}

func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

func cleanText(raw string, maximum int) (string, bool) {
	raw = strings.TrimSpace(raw)
	n := utf8.RuneCountInString(raw)
	return raw, n >= 1 && n <= maximum && !strings.ContainsFunc(raw, unicode.IsControl)
}

func (m *setupSMTP) validate() error {
	invalid := bad("Invalid e-mail server settings.")
	if !validHostname(m.Host) || m.Port < 1 || m.Port > 65535 || !slices.Contains([]string{"none", "starttls", "tls"}, m.Security) {
		return invalid
	}
	from, ok := plainAddress(m.From)
	if !ok {
		return invalid
	}
	m.From = from
	if m.FromName != "" {
		if m.FromName, ok = cleanText(m.FromName, 100); !ok {
			return invalid
		}
	}
	if len(m.Username) > 256 || len(m.Password) > 1024 || (m.Password != "" && m.Username == "") || strings.ContainsFunc(m.Username, unicode.IsControl) {
		return invalid
	}
	// The realm would send the password in clear to a remote relay on every message;
	// the test refuses that (net/smtp), completion must not accept it either.
	if m.Security == "none" && m.Password != "" && m.Host != "localhost" && !net.ParseIP(m.Host).IsLoopback() {
		return bad("A password is only sent over TLS or STARTTLS, or to a relay on this machine.")
	}
	return nil
}

// keycloak renders the settings as the realm's smtpServer map, whose values are strings.
func (m setupSMTP) keycloak() map[string]string {
	out := map[string]string{"host": m.Host, "port": strconv.Itoa(m.Port), "from": m.From, "fromDisplayName": m.FromName,
		"ssl": strconv.FormatBool(m.Security == "tls"), "starttls": strconv.FormatBool(m.Security == "starttls"), "auth": strconv.FormatBool(m.Username != "")}
	if m.Username != "" {
		out["user"], out["password"] = m.Username, m.Password
	}
	return out
}

// send delivers one test message with the same settings the realm will use.
// net/smtp refuses to send credentials over an unencrypted remote connection.
func (m setupSMTP) send(ctx context.Context, to string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	address := net.JoinHostPort(m.Host, strconv.Itoa(m.Port))
	secure := &tls.Config{ServerName: m.Host, MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var e error
	if m.Security == "tls" {
		conn, e = (&tls.Dialer{NetDialer: dialer, Config: secure}).DialContext(ctx, "tcp", address)
	} else {
		conn, e = dialer.DialContext(ctx, "tcp", address)
	}
	if e != nil {
		return e
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	client, e := smtp.NewClient(conn, m.Host)
	if e != nil {
		conn.Close()
		return e
	}
	defer client.Close()
	if m.Security == "starttls" {
		if e = client.StartTLS(secure); e != nil {
			return e
		}
	}
	if m.Username != "" {
		if e = client.Auth(smtp.PlainAuth("", m.Username, m.Password, m.Host)); e != nil {
			return e
		}
	}
	if e = client.Mail(m.From); e != nil {
		return e
	}
	if e = client.Rcpt(to); e != nil {
		return e
	}
	body, e := client.Data()
	if e != nil {
		return e
	}
	from := (&mail.Address{Name: m.FromName, Address: m.From}).String()
	message := "From: " + from + "\r\nTo: " + to + "\r\nSubject: Milvago\r\nDate: " + time.Now().UTC().Format(time.RFC1123Z) +
		"\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nMilvago can send e-mail with these settings.\r\n"
	if _, e = body.Write([]byte(message)); e != nil {
		return e
	}
	if e = body.Close(); e != nil {
		return e
	}
	return client.Quit()
}

func (a *App) setupSMTPTest(w http.ResponseWriter, r *http.Request) {
	if !a.setupGuard(w, r, "setup-smtp") {
		return
	}
	var body struct {
		SMTP setupSMTP `json:"smtp"`
		To   string    `json:"to"`
	}
	if e := decode(w, r, &body); e != nil {
		a.fail(w, e)
		return
	}
	to, ok := plainAddress(body.To)
	if !ok {
		a.fail(w, bad("Invalid recipient address."))
		return
	}
	if e := body.SMTP.validate(); e != nil {
		a.fail(w, e)
		return
	}
	if e := body.SMTP.send(r.Context(), to); e != nil {
		// The administrator needs the server's own answer to fix the settings; it
		// never contains the password, which is only ever sent, not echoed.
		detail := e.Error()
		if len(detail) > 200 {
			detail = detail[:200]
		}
		a.fail(w, apiError{502, "smtp_failed", "The mail server did not accept the test message: " + detail})
		return
	}
	reply(w, 200, map[string]bool{"sent": true})
}

type setupRequest struct {
	Admin struct {
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Password  string `json:"password"`
	} `json:"admin"`
	Organization struct {
		Name            string `json:"name"`
		PublicURL       string `json:"public_url"`
		DefaultLanguage string `json:"default_language"`
	} `json:"organization"`
	AdminTOTP  bool                   `json:"admin_totp"`
	RequireMFA bool                   `json:"require_mfa"`
	SMTP       *setupSMTP             `json:"smtp"`
	Privacy    *IdentityPrivacyConfig `json:"privacy"`
	License    string                 `json:"license"`
}

func (s *setupRequest) validate() error {
	var ok bool
	if s.Admin.Email, ok = plainAddress(s.Admin.Email); !ok {
		return bad("Enter a valid administrator e-mail address.")
	}
	if s.Admin.FirstName, ok = cleanText(s.Admin.FirstName, 100); !ok {
		return bad("Enter the administrator's first name.")
	}
	if s.Admin.LastName, ok = cleanText(s.Admin.LastName, 100); !ok {
		return bad("Enter the administrator's last name.")
	}
	// The realm's password policy has the final word; this only rejects what can
	// never pass, before anything is created.
	if n := utf8.RuneCountInString(s.Admin.Password); n < 12 || n > 128 || strings.EqualFold(s.Admin.Password, s.Admin.Email) {
		return bad("The password must contain 12 to 128 characters and differ from the e-mail address.")
	}
	if s.Organization.Name, ok = cleanText(s.Organization.Name, 120); !ok {
		return bad("Name must contain 1 to 120 characters.")
	}
	s.Organization.PublicURL = strings.TrimRight(strings.TrimSpace(s.Organization.PublicURL), "/")
	if !validOrigin(s.Organization.PublicURL) {
		return bad("Public URL must be an HTTPS origin (HTTP permitted only on explicit loopback).")
	}
	if !slices.Contains(consoleLanguages, s.Organization.DefaultLanguage) {
		return bad("Default language must be one of fr, en, es, pt-BR.")
	}
	if s.SMTP != nil {
		if e := s.SMTP.validate(); e != nil {
			return e
		}
	}
	if s.Privacy != nil {
		if e := validatePrivacyConfig(*s.Privacy); e != nil {
			return e
		}
	}
	return nil
}

func (a *App) setupComplete(w http.ResponseWriter, r *http.Request) {
	if !a.setupGuard(w, r, "setup-complete") {
		return
	}
	var body setupRequest
	// Fields the wizard does not show keep the server's defaults, as in PUT /api/privacy.
	privacy := defaultPrivacy()
	body.Privacy = &privacy
	if e := decode(w, r, &body); e != nil {
		a.fail(w, e)
		return
	}
	if e := body.validate(); e != nil {
		a.fail(w, e)
		return
	}
	if e := a.completeSetup(r.Context(), body); e != nil {
		a.fail(w, e)
		return
	}
	a.forgetLicense()
	http.SetCookie(w, &http.Cookie{Name: cookieName("setup"), Value: "", Path: "/api/setup", HttpOnly: true, Secure: a.config.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	// With a second factor chosen, the first sign-in asks for the OTP level at once:
	// password and TOTP enrolment in one pass, instead of a password-only session
	// that the MFA requirement would immediately send back to authenticate again.
	login := "/auth/login"
	if body.AdminTOTP || body.RequireMFA {
		login += "?mfa=1"
	}
	reply(w, 200, map[string]string{"login": login})
}

func (a *App) completeSetup(ctx context.Context, body setupRequest) (err error) {
	// Once started, completion runs to its end or undoes itself: a client that
	// disconnected after the account was created cancelled the commit and the cleanup
	// alike, and left an account that blocked every later attempt (2026-09-24).
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, setupLockKey); e != nil {
		return e
	}
	var org string
	var pending bool
	if e = tx.QueryRow(ctx, `SELECT organization_id,bootstrap_email='' AND NOT bootstrap_consumed FROM app_config FOR UPDATE`).Scan(&org, &pending); e != nil {
		return e
	}
	if !pending {
		return errSetupClosed
	}
	if _, e = tx.Exec(ctx, sqlSetOrganizationContext, org); e != nil {
		return e
	}
	var members int
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE organization_id=$1`, org).Scan(&members); e != nil {
		return e
	}
	if members != 0 {
		return errSetupClosed
	}
	// Checked before any account exists, so a refused licence leaves nothing behind.
	if e = setupLicense(ctx, tx, body.License); e != nil {
		return e
	}
	admin, e := a.identityAdmin(ctx)
	if e != nil {
		return e
	}
	// Never take over an account that already exists in the realm.
	status, _, raw, e := admin.call("GET", "/users?email="+url.QueryEscape(body.Admin.Email)+"&exact=true", nil)
	if e != nil {
		return e
	}
	var existing []identityUser
	if status != 200 || json.Unmarshal(raw, &existing) != nil {
		return apiError{502, "identity_unavailable", "Could not query identity users."}
	}
	if len(existing) != 0 {
		return apiError{409, "identity_exists", "An account with this e-mail address already exists."}
	}
	if body.SMTP != nil {
		if status, _, _, e = admin.call("PUT", "", map[string]any{"smtpServer": body.SMTP.keycloak()}); e != nil {
			return e
		}
		if status != 204 {
			return apiError{502, "identity_unavailable", "Could not save the e-mail server settings."}
		}
	}
	actions := []string{}
	if body.AdminTOTP {
		actions = append(actions, "CONFIGURE_TOTP")
	}
	status, header, raw, e := admin.call("POST", "/users", map[string]any{
		"username": body.Admin.Email, "email": body.Admin.Email, "firstName": body.Admin.FirstName, "lastName": body.Admin.LastName,
		"enabled": true, "emailVerified": true, "requiredActions": actions,
		"credentials": []map[string]any{{"type": "password", "value": body.Admin.Password, "temporary": false}},
	})
	if e != nil {
		return e
	}
	switch status {
	case 201:
	case 409:
		return apiError{409, "identity_exists", "An account with this e-mail address already exists."}
	case 400:
		var refusal struct {
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(raw, &refusal)
		message := "The password does not satisfy the identity provider's password policy."
		if d, ok := cleanText(refusal.Description, 300); ok {
			message = d
		}
		return apiError{400, "password_rejected", message}
	default:
		return apiError{502, "identity_unavailable", "Could not create the administrator account."}
	}
	location, e := url.Parse(header.Get("Location"))
	subject := ""
	if e == nil {
		subject = path.Base(location.Path)
	}
	if subject == "" || subject == "." || subject == "/" {
		return apiError{502, "identity_unavailable", "The created administrator account could not be identified."}
	}
	// From here on, a failure must not leave an account behind: the next attempt
	// would otherwise be refused as an existing identity.
	defer func() {
		if err != nil {
			// A context of its own: the failure may be the completion's deadline itself.
			cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer cancelCleanup()
			// A commit that failed from here may still have happened: then the account is
			// the administrator, and deleting it would lock the instance out.
			var committed bool
			if a.db.QueryRow(cleanupCtx, `SELECT bootstrap_email=$1 FROM app_config`, body.Admin.Email).Scan(&committed) == nil && committed {
				err = nil
				return
			}
			cleanup, e := a.identityAdmin(cleanupCtx)
			status := 0
			if e == nil {
				status, _, _, e = cleanup.call("DELETE", "/users/"+url.PathEscape(subject), nil)
			}
			if e != nil || status != 204 {
				err = fmt.Errorf("%w (and the created identity account could not be removed)", err)
			}
		}
	}()
	if _, e = tx.Exec(ctx, `UPDATE app_config SET bootstrap_email=$1,public_url=$2,public_url_confirmed=true,default_language=$3`, body.Admin.Email, body.Organization.PublicURL, body.Organization.DefaultLanguage); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE organizations SET name=$1 WHERE id=$2`, body.Organization.Name, org); e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, `UPDATE settings SET require_mfa=$1 WHERE organization_id=$2`, body.RequireMFA, org)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return errors.New("organization settings were not updated")
	}
	if body.Privacy != nil {
		raw, _ := json.Marshal(*body.Privacy)
		if _, e = tx.Exec(ctx, `INSERT INTO privacy_settings(organization_id,configuration) VALUES($1,$2) ON CONFLICT(organization_id) DO UPDATE SET configuration=EXCLUDED.configuration,revision=privacy_settings.revision+1,updated_at=now()`, org, raw); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(ctx, `DELETE FROM setup_sessions`); e != nil {
		return e
	}
	if e = audit(ctx, tx, org, "setup", "setup.completed", org); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
