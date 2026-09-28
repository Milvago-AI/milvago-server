package app

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func (a *App) startDeviceAssociation(w http.ResponseWriter, r *http.Request) {
	tx, org, device, e := a.deviceTx(r)
	if e != nil {
		a.fail(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	token := randomToken()
	expiry := time.Now().UTC().Add(10 * time.Minute)
	if _, e = tx.Exec(r.Context(), `DELETE FROM device_association_requests WHERE device_id=$1`, device); e == nil {
		_, e = tx.Exec(r.Context(), `INSERT INTO device_association_requests(organization_id,device_id,token_hash,expires_at) VALUES($1,$2,$3,$4)`, org, device, hash(token), expiry)
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		a.fail(w, e)
		return
	}
	reply(w, 200, map[string]any{"verification_url": a.browserOrigin() + "/auth/device?token=" + token, "expires_at": expiry})
}

var associationPage = template.Must(template.New("association").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Milvago installation association</title><main><h1>Associate this installation</h1><p>Organization: {{.Organization}}</p><p>Installation: {{.Hostname}}</p><p><strong>Continue only if this is your own machine and you started the association from it yourself.</strong> If someone sent you this link, close this page.</p><p> Your verified identity will identify new activity for eight hours. This does not create console membership.</p><form method="post" action="/auth/device"><input type="hidden" name="token" value="{{.Token}}"><input type="hidden" name="confirmation" value="{{.Confirmation}}"><button type="submit">Continue with identity provider</button></form></main></html>`))

func (a *App) deviceAssociation(w http.ResponseWriter, r *http.Request) {
	if e := a.deviceAssociationRequest(w, r); e != nil {
		a.fail(w, e)
	}
}
func (a *App) deviceAssociationRequest(w http.ResponseWriter, r *http.Request) error {
	// Unauthenticated, and each request costs a lookup plus a tenant transaction.
	if e := a.checkPublicRequest(r, "device-association", 120, 1200); e != nil {
		return e
	}
	token := r.URL.Query().Get("token")
	if r.Method == "POST" {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if r.ParseForm() != nil {
			return bad("Invalid confirmation form.")
		}
		token = r.PostForm.Get("token")
		c, e := r.Cookie(a.cookieName("association"))
		if e != nil || r.Header.Get("Origin") != a.browserOrigin() || !equal(c.Value, r.PostForm.Get("confirmation")) {
			return forbidden()
		}
		a.cookie(w, a.cookieName("association"), "", -1)
	}
	if len(token) != 43 {
		return bad("Invalid association link.")
	}
	var org, device string
	if a.db.QueryRow(r.Context(), `SELECT organization_id,device_id FROM association_identity($1)`, hash(token)).Scan(&org, &device) != nil {
		return apiError{410, "association_expired", "The association link expired or was already used."}
	}
	tx, e := tenantTx(r.Context(), a.db, org)
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	// The person at the machine signs in to the realm of the machine's organization.
	realm, e := a.organizationRealm(r.Context(), tx, org)
	if e != nil {
		return e
	}
	identity, e := a.currentOIDCFor(r.Context(), realm)
	if e != nil {
		return e
	}
	var hostname, sealedName, name string
	if e = tx.QueryRow(r.Context(), `SELECT d.hostname,COALESCE(d.hostname_ciphertext,''),o.name FROM devices d JOIN organizations o ON o.id=d.organization_id WHERE d.id=$1 AND d.status='approved'`, device).Scan(&hostname, &sealedName, &name); e != nil {
		return forbidden()
	}
	// The real machine name, not the alias the console stores in clear: the person
	// must be able to tell that the link comes from their own machine. Shown an alias,
	// a colleague sent this link by someone else could not, and would sign every
	// action of that machine for eight hours (audit of 2026-09-24). Only the holder of
	// the one-use link sees it, and that holder is the machine.
	if machine, e := a.openIdentity(org, "device-name:"+device, sealedName); e == nil && machine != "" {
		hostname = machine
	}
	if r.Method == "GET" {
		// A no-referrer navigation gives browser form POSTs an opaque Origin.
		// Send only the origin, never the one-use association token in the URL.
		w.Header().Set("Referrer-Policy", "strict-origin")
		identityURL, _ := url.Parse(identity.oauth.Endpoint.AuthURL)
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self' "+identityURL.Scheme+"://"+identityURL.Host+"; base-uri 'none'; frame-ancestors 'none'")
		confirmation := randomToken()
		a.cookie(w, a.cookieName("association"), confirmation, 600)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		return associationPage.Execute(w, map[string]string{"Organization": name, "Hostname": hostname, "Token": token, "Confirmation": confirmation})
	}
	state, binding, nonce, verifier := randomToken(), randomToken(), randomToken(), oauth2.GenerateVerifier()
	if _, e = tx.Exec(r.Context(), `INSERT INTO login_attempts(state_hash,binding_hash,verifier,nonce,expires_at,association_org,association_device,association_hash,realm) VALUES($1,$2,$3,$4,now()+interval '10 minutes',$5,$6,$7,$8)`, hash(state), hash(binding), verifier, nonce, org, device, hash(token), realm); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	a.cookie(w, a.cookieName("login"), binding, 600)
	http.Redirect(w, r, identity.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("prompt", "select_account")), 302)
	return nil
}

type deviceAssociationIdentity struct {
	subject string
	email   string
	name    string
	claims  map[string]json.RawMessage
}

func (a *App) finishDeviceAssociation(w http.ResponseWriter, r *http.Request, org, device string, digest []byte, identity deviceAssociationIdentity) error {
	subject, email, name, claims := identity.subject, identity.email, identity.name, identity.claims
	// A right-to-left display name legitimately carries direction marks; they are
	// dropped rather than refused (the check refuses them for device-chosen names).
	name = identityText(name)
	if !validMetadata(subject, 500) || !validMetadata(email, 320) || !validMetadata(name, 200) {
		return bad("Invalid verified identity metadata.")
	}
	tx, e := tenantTx(r.Context(), a.db, org)
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	var found string
	if e = tx.QueryRow(r.Context(), `SELECT id FROM devices WHERE id=$1 AND status='approved' FOR UPDATE`, device).Scan(&found); e != nil {
		return forbidden()
	}
	tag, e := tx.Exec(r.Context(), `DELETE FROM device_association_requests WHERE token_hash=$1 AND device_id=$2 AND expires_at>now()`, digest, device)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return apiError{410, "association_expired", "The association link expired or was already used."}
	}
	actor, e := a.associateIdentity(r.Context(), tx, org, subject, email, name)
	if e != nil {
		return e
	}
	privacy, e := a.readPrivacy(r.Context(), tx, org)
	if e != nil {
		return e
	}
	team := ""
	if privacy.Config.TeamClaim != "" {
		if raw, ok := claims[privacy.Config.TeamClaim]; ok {
			if json.Unmarshal(raw, &team) != nil || len(team) > 120 || !validMetadata(team, 120) {
				return bad("Invalid verified team claim.")
			}
		}
	}
	if tag, e = tx.Exec(r.Context(), "UPDATE collaborators SET team=$2 WHERE id=$1", actor, team); e != nil || tag.RowsAffected() != 1 {
		return bad("Verified team was not stored.")
	}
	if _, e = tx.Exec(r.Context(), `INSERT INTO device_collaborators(organization_id,device_id,collaborator_id,bound_at,expires_at) VALUES($1,$2,$3,$4::timestamptz,$4::timestamptz+interval '8 hours') ON CONFLICT(organization_id,device_id) DO UPDATE SET collaborator_id=excluded.collaborator_id,bound_at=excluded.bound_at,expires_at=excluded.expires_at`, org, device, actor, time.Now().UTC()); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, org, "collaborator:"+actor, "device.identity.associate", device); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, e = w.Write([]byte(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Milvago</title><main><h1>Installation associated</h1><p>Your verified identity is associated with new activity on this installation for eight hours. You can close this page.</p></main></html>`))
	return e
}
func (a *App) unbindDeviceAssociation(w http.ResponseWriter, r *http.Request) {
	tx, org, device, e := a.deviceTx(r)
	if e != nil {
		a.fail(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	// Audited only when something was unbound: the log is append-only and a device
	// repeating the call would otherwise fill it (audit of 2026-09-24).
	tag, e := tx.Exec(r.Context(), `DELETE FROM device_collaborators WHERE device_id=$1`, device)
	if e == nil && tag.RowsAffected() > 0 {
		e = audit(r.Context(), tx, org, "device:"+device, "device.identity.remove", device)
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		a.fail(w, e)
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}

// identityText cleans a name or e-mail the identity provider supplies: direction
// controls are legitimate in a right-to-left name but an override (U+202E) renders
// one person as another in every list that shows them, and other control characters
// or line separators have no place in either. They are dropped, not refused, so a
// sign-in never fails on them.
func identityText(s string) string {
	return strings.Map(func(c rune) rune {
		if unicode.Is(unicode.Bidi_Control, c) || unicode.IsControl(c) || c == '\u2028' || c == '\u2029' {
			return -1
		}
		return c
	}, s)
}
