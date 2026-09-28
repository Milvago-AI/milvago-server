package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// InstallerProvision is used by the authorized server-side package builder.
// The list/create APIs never serialize this secret-bearing object.
type InstallerProvision struct {
	ProfileID       string    `json:"profile_id"`
	Edition         string    `json:"edition"`
	Platform        string    `json:"platform"`
	Version         string    `json:"version"`
	ServerURL       string    `json:"server_url"`
	PolicyPublicKey string    `json:"policy_public_key"`
	UpdatePublicKey string    `json:"update_public_key,omitempty"`
	BootstrapToken  string    `json:"bootstrap_token"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func (a *App) registerInstallerRoutes() {
	a.registerReinstallationRoute()
	// One durable deployment key per organization replaces the short-lived,
	// per-platform installation package. The download names the platform; the key
	// names the organization.
	a.console("GET /api/deployment-key", permInstallersManage, a.organizationKey)
	a.console("POST /api/deployment-key/rotate", permInstallersManage, a.rotateOrganizationKey)
	a.console("POST /api/deployment-key/revoke", permInstallersManage, a.revokeOrganizationKey)
	a.console("GET /api/installer/{platform}", permInstallersManage, a.downloadInstaller)
	a.sessionOnly("POST /api/installer/windows/provision", permInstallersManage, a.downloadWindowsProvision)
	a.console("GET /api/installer/windows/script", permInstallersManage, a.downloadWindowsScript)
	if Edition == "commercial" {
		// Reached from an organization's own page, without switching session into it.
		a.console("GET /api/organizations/{id}/deployment-key", permInstallersManage, a.organizationKey)
		a.console("POST /api/organizations/{id}/deployment-key/rotate", permInstallersManage, a.rotateOrganizationKey)
		a.console("POST /api/organizations/{id}/deployment-key/revoke", permInstallersManage, a.revokeOrganizationKey)
	}
	a.mux.HandleFunc("POST /v2/install", func(w http.ResponseWriter, r *http.Request) {
		if err := a.installEndpoint(w, r); err != nil {
			a.fail(w, err)
		}
	})
}
func installerUnavailable() error {
	return apiError{401, "installer_unauthorized", "Installer provisioning is invalid, expired or revoked."}
}
func (a *App) installerProvision(ctx context.Context, tx pgx.Tx, org, id string) (InstallerProvision, error) {
	var p InstallerProvision
	var encrypted string
	if len(a.config.UpdatePublicKey) != ed25519.PublicKeySize {
		return p, apiError{503, "installer_unavailable", "Installer update verification key is not configured."}
	}
	// `id` names the platform being downloaded, not a package: the organization has a
	// single durable deployment key, and the version is whatever the current release
	// carries at build time.
	if !slices.Contains([]string{"windows", "linux"}, id) {
		return p, bad("Unsupported installer platform.")
	}
	var keyID string
	err := tx.QueryRow(ctx, `SELECT id,secret_ciphertext FROM installer_profiles WHERE organization_id=$1 AND platform IS NULL AND NOT revoked AND expires_at>now() AND edition=$2 ORDER BY created_at DESC LIMIT 1 FOR SHARE`, org, Edition).Scan(&keyID, &encrypted)
	if err == pgx.ErrNoRows {
		return p, apiError{409, "deployment_key_missing", "This organization has no active deployment key. Rotate it to issue one."}
	}
	if err != nil {
		return p, err
	}
	p.ProfileID = keyID
	p.Edition = Edition
	p.Platform = id
	plain, err := a.openShadow(org, "deployment-key:"+org, encrypted)
	if err != nil {
		// A deployment key never expires, so it is the one sealed value that can
		// outlive the content key that sealed it. Saying so, with the remedy, beats
		// an internal error: rotating re-seals it under the active version.
		return p, apiError{409, "deployment_key_unreadable", "This organization's deployment key was sealed with a content key this server no longer loads. Rotate it to issue a readable one."}
	}
	p.BootstrapToken = string(plain)
	p.ServerURL = a.publicOriginIn(ctx, tx)
	p.PolicyPublicKey = base64.StdEncoding.EncodeToString(a.policyKey(org).Public().(ed25519.PublicKey))
	p.UpdatePublicKey = base64.StdEncoding.EncodeToString(a.config.UpdatePublicKey)
	return p, nil
}

type installationRequest struct {
	InstallationID     string   `json:"installation_id"`
	InstallationSecret string   `json:"installation_secret"`
	Hostname           string   `json:"hostname"`
	Platform           string   `json:"platform"`
	Version            string   `json:"version"`
	Capabilities       []string `json:"capabilities"`
	// Outside the retry hash: it only decides the approval of a first installation.
	MachineDomains []machineDomain `json:"machine_domains"`
}

func validateInstallationRequest(body *installationRequest) error {
	rawSecret, err := base64.RawURLEncoding.DecodeString(body.InstallationSecret)
	if err != nil || len(rawSecret) != 32 || len(body.InstallationSecret) != 43 || !uuidPattern.MatchString(body.InstallationID) || !validMetadata(body.Hostname, 120) || !slices.Contains([]string{"windows", "linux"}, body.Platform) || !versionPattern.MatchString(body.Version) || len(body.Capabilities) > 50 {
		return bad("Invalid installation identity or endpoint metadata.")
	}
	if !validMachineDomains(body.MachineDomains) {
		return bad("Invalid machine domains.")
	}
	if body.Capabilities == nil {
		body.Capabilities = []string{}
	}
	for _, capability := range body.Capabilities {
		if !categoryPattern.MatchString(capability) {
			return bad("Invalid capability identifier.")
		}
	}
	slices.Sort(body.Capabilities)
	body.Capabilities = slices.Compact(body.Capabilities)
	return nil
}

func (a *App) installEndpoint(w http.ResponseWriter, r *http.Request) error {
	if err := a.checkPublicRequest(r, "install", 300, 1200); err != nil {
		return err
	}
	bearer := r.Header.Get("Authorization")
	if !strings.HasPrefix(bearer, "Bearer ") || len(bearer) != 50 {
		return installerUnavailable()
	}
	token := strings.TrimPrefix(bearer, "Bearer ")
	var body installationRequest
	if err := decode(w, r, &body); err != nil {
		return err
	}
	if err := validateInstallationRequest(&body); err != nil {
		return err
	}
	// The retry key is independent of the distributable bootstrap token. Merely
	// knowing an installation UUID never authorizes credential recovery.
	requestBytes, _ := json.Marshal(struct {
		Hostname, Platform, Version string
		Capabilities                []string
	}{body.Hostname, body.Platform, body.Version, body.Capabilities})
	requestHash := hash(string(requestBytes))
	var org string
	if err := a.db.QueryRow(r.Context(), `SELECT organization_id FROM installer_identity($1)`, hash(token)).Scan(&org); err == pgx.ErrNoRows {
		return installerUnavailable()
	} else if err != nil {
		return err
	}
	// Bounded before tenant work, on the credential presented rather than on the
	// caller's address: the point is to bound one key, whatever it enrols from. Spent
	// only once the key is known, so invented keys cannot fill the per-key window.
	if err := a.checkIngestRate(r.Context(), "install:"+string(hash(token)), deviceBudget["/v2/install"]); err != nil {
		return err
	}
	tx, err := tenantTx(r.Context(), a.db, org)
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	var keyID, edition string
	var uses, maximum int
	err = tx.QueryRow(r.Context(), `SELECT id,edition,uses,max_uses FROM installer_profiles WHERE secret_hash=$1 AND platform IS NULL AND NOT revoked AND expires_at>now() FOR UPDATE`, hash(token)).Scan(&keyID, &edition, &uses, &maximum)
	if err == pgx.ErrNoRows {
		return installerUnavailable()
	}
	if err != nil {
		return err
	}
	// A deployment key carries neither platform nor version, so neither can be
	// re-checked against it. The edition still can, and must: a Community key must
	// never install a commercial agent.
	if edition != Edition {
		return installerUnavailable()
	}
	// An installation is recovered by the identity the agent chose, not by the key
	// that first bought it: the sealing purpose uses the key stored with the row, so
	// a rotation leaves previously sealed credentials readable and a repair run from
	// a *current* installer recovers the device instead of creating a second one.
	// A repair run from an installer whose key was rotated away is refused above,
	// like any other use of a retired key.
	// The organization is named explicitly as well as enforced by row-level
	// security: isolation this important should not rest on one mechanism.
	var storedKeyID, deviceID, ciphertext, status string
	var secretHash, storedRequestHash []byte
	err = tx.QueryRow(r.Context(), `SELECT i.profile_id,i.device_id,i.credential_ciphertext,i.installation_secret_hash,i.request_hash,d.status FROM installer_installations i JOIN devices d ON d.organization_id=i.organization_id AND d.id=i.device_id WHERE i.organization_id=$1 AND i.installation_id=$2`, org, body.InstallationID).Scan(&storedKeyID, &deviceID, &ciphertext, &secretHash, &storedRequestHash, &status)
	if err == nil {
		// A device awaiting approval recovers its credential; a revoked one never
		// does. Refusing a pending device here would make a manual-approval fleet
		// unrepairable until every poste is approved.
		if !equal(string(hash(body.InstallationSecret)), string(secretHash)) || !bytes.Equal(requestHash, storedRequestHash) || status == "revoked" || ciphertext == "" {
			return installerUnavailable()
		}
		plain, e := a.openShadow(org, "installer-installation:"+storedKeyID+":"+body.InstallationID, ciphertext)
		if e != nil {
			return e
		}
		if err = tx.Commit(r.Context()); err != nil {
			return err
		}
		reply(w, 200, map[string]string{"device_id": deviceID, "credential": string(plain)})
		return nil
	}
	if err != pgx.ErrNoRows {
		return err
	}
	if uses >= maximum {
		return apiError{409, "installer_exhausted", "Deployment key installation limit has been reached."}
	}
	if err = a.checkDeviceQuota(r.Context(), tx, org); err != nil {
		return err
	}
	kind := "browser"
	if Edition == "commercial" {
		kind = "native"
	}
	// The MSI path is no more trusted than a token enrollment: an organization that
	// requires manual approval gets it here too.
	status, err = a.approvalStatus(r, tx, org, body.MachineDomains)
	if err != nil {
		return err
	}
	credential := randomToken()
	caps, _ := json.Marshal(body.Capabilities)
	err = tx.QueryRow(r.Context(), `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,kind,capabilities,status,machine_domains) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, org, hash(credential), body.Hostname, body.Platform, body.Version, kind, caps, status, machineDomainsJSON(body.MachineDomains)).Scan(&deviceID)
	if err == nil {
		err = a.storeDeviceName(r.Context(), tx, org, deviceID, body.Hostname)
	}
	if err != nil {
		return err
	}
	ciphertext, err = a.sealShadow(org, "installer-installation:"+keyID+":"+body.InstallationID, []byte(credential))
	if err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), `INSERT INTO installer_installations(organization_id,profile_id,installation_id,installation_secret_hash,request_hash,device_id,credential_ciphertext) VALUES($1,$2,$3,$4,$5,$6,$7)`, org, keyID, body.InstallationID, hash(body.InstallationSecret), requestHash, deviceID, ciphertext); err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), `UPDATE installer_profiles SET uses=uses+1 WHERE id=$1`, keyID); err != nil {
		return err
	}
	if err = audit(r.Context(), tx, org, "device:"+deviceID, "device.install", keyID); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	reply(w, 201, map[string]string{"device_id": deviceID, "credential": credential})
	return nil
}
