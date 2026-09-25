package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// EnrollmentRule approves a new device whose source address is inside CIDR and, when Domain
// is set, whose declared machine domain (Active Directory or realm DNS name, or Entra tenant
// ID) is also Domain. A domain is declared by the machine and proves nothing on its own, so a
// rule never holds a domain without a network (product decision of 2026-09-23).
type EnrollmentRule struct {
	CIDR   string `json:"cidr"`
	Domain string `json:"domain"`
}
type EnrollmentConfig struct {
	Approval string `json:"approval"`
	// CIDRs are the rules of configurations written before rules existed: a network, no domain.
	CIDRs []string         `json:"cidrs"`
	Rules []EnrollmentRule `json:"rules"`
}
type CollectionConfig struct {
	Enabled              bool `json:"enabled"`
	StoreContent         bool `json:"store_content"`
	StoreFileNames       bool `json:"store_file_names"`
	ContentRetentionDays int  `json:"content_retention_days"`
}
type ServiceConfig struct {
	ID          string   `json:"id"`
	Domains     []string `json:"domains"`
	Mode        string   `json:"mode"`
	RedirectURL string   `json:"redirect_url"`
	Enabled     bool     `json:"enabled"`
}
type ProtectionConfig struct {
	BlockUploads bool     `json:"block_uploads"`
	Keywords     []string `json:"keywords"`
	Exact        string   `json:"exact"`
	Unicode      string   `json:"unicode"`
	Fuzzy        string   `json:"fuzzy"`
	Exceptions   []string `json:"exceptions"`
	Message      string   `json:"message"`
}
type PrivacyRule struct {
	ID              string `json:"id"`
	Label           string `json:"label"`
	Pattern         string `json:"pattern"`
	CaseInsensitive bool   `json:"case_insensitive"`
	Enabled         bool   `json:"enabled"`
}
type PrivacyConfig struct {
	Enabled     bool          `json:"enabled"`
	Review      bool          `json:"review"`
	Types       []string      `json:"types"`
	CustomRules []PrivacyRule `json:"custom_rules"`
}
type ClassificationConfig struct {
	Browser      []string `json:"browser"`
	Coding       []string `json:"coding"`
	MedicalTerms []string `json:"medical_terms"`
}
type DestinationConfig struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Endpoint string `json:"endpoint"`
	Enabled  bool   `json:"enabled"`
	Token    string `json:"token,omitempty"`
	TokenSet bool   `json:"token_set,omitempty"`
}
type UpdateConfig struct {
	Enabled        bool     `json:"enabled"`
	DeviceIDs      []string `json:"device_ids"`
	Percentage     int      `json:"percentage"`
	PausedVersions []string `json:"paused_versions"`
}
type OperationsConfig struct {
	MetricsEnabled bool                `json:"metrics_enabled"`
	Destinations   []DestinationConfig `json:"destinations"`
	Updates        UpdateConfig        `json:"updates"`
}
type ShadowConfig struct {
	Discovery      DiscoveryConfig      `json:"discovery"`
	ModelAccess    []ModelAccessRule    `json:"model_access"`
	Enrollment     EnrollmentConfig     `json:"enrollment"`
	Collection     CollectionConfig     `json:"collection"`
	Services       []ServiceConfig      `json:"services"`
	Protection     ProtectionConfig     `json:"protection"`
	Privacy        PrivacyConfig        `json:"privacy"`
	Classification ClassificationConfig `json:"classification"`
	Operations     OperationsConfig     `json:"operations"`
}
type InheritedFrom struct {
	OrganizationID string `json:"organization_id,omitempty"`
	// GroupID is set when the section's value comes from the device group's
	// override rather than from an organization.
	GroupID string `json:"group_id,omitempty"`
	Name    string `json:"name"`
}
type ShadowSettings struct {
	ModelCatalog    []ModelCatalogEntry      `json:"model_catalog"`
	Revision        int64                    `json:"revision"`
	Config          ShadowConfig             `json:"config"`
	InheritSections []string                 `json:"inherit_sections"`
	InheritedFrom   map[string]InheritedFrom `json:"inherited_from"`
	Capabilities    map[string]bool          `json:"capabilities"`
}

var shadowSections = []string{"enrollment", "collection", "services", "protection", "privacy", "classification", "operations", "model_access"}

// The categories an administrator may select. privacyTypes are the ones a masking rule
// can target; classificationTypes adds the ones that only classify.
//
// classificationTypes is NOT the event-label vocabulary, and the difference is
// deliberate rather than drift. The agent (endpoint/src/shadow.rs) and the extension
// (endpoint/extension/detection-runtime.js) each enforce eleven labels at their edge --
// these ten plus "custom", the label an administrator's own rule carries. "custom" has
// no fixed sensitivity, so it cannot appear in a list whose job is to map a label to
// one; ingestion reads an unknown label as sensitivity "unknown" rather than refusing
// it (shadow_endpoint.go, the classification block).
var privacyTypes = []string{"email", "phone", "iban", "card", "social_id", "ssn_us", "ip"}
var classificationTypes = []string{"email", "phone", "iban", "card", "social_id", "ssn_us", "ip", "source_code", "medical", "keyword"}

// defaultMedicalTerms are the built-in triggers for the "medical" label; administrators
// can replace them under Shadow AI → Sensibilité des usages → Termes médicaux.
func defaultMedicalTerms() []string {
	return []string{"diagnostic", "ordonnance", "prescription", "medical record", "dossier médical"}
}

// The services offered by default are the providers of this edition's built-in
// catalogue, read from the same document the instance publishes: one source, so the
// Services page cannot name a site the catalogue does not, nor state its domains in
// another order -- `validateCatalogPolicy` compares those domains exactly, and the
// hand-written list this replaced had drifted on notebooklm and perplexity.
var catalog = builtinServices()

func builtinServices() []ServiceConfig {
	c, e := decodeDetection(detectionFactory)
	if e != nil {
		return nil
	}
	restrictEditionProviders(&c)
	services := []ServiceConfig{}
	for _, p := range c.Providers {
		services = append(services, ServiceConfig{ID: p.ID, Domains: append(append([]string{}, p.Domains...), p.Aliases...)})
	}
	return services
}

func defaultShadowConfig() ShadowConfig {
	c := ShadowConfig{ModelAccess: []ModelAccessRule{}, Enrollment: EnrollmentConfig{"manual", []string{}, []EnrollmentRule{}}, Collection: CollectionConfig{true, false, false, 7}, Services: []ServiceConfig{}, Protection: ProtectionConfig{false, []string{}, "block", "block", "off", []string{}, "This action is restricted by your organization."}, Privacy: PrivacyConfig{false, true, []string{}, []PrivacyRule{}}, Classification: ClassificationConfig{[]string{"iban", "card", "social_id"}, []string{}, defaultMedicalTerms()}, Operations: OperationsConfig{false, []DestinationConfig{}, UpdateConfig{false, []string{}, 100, []string{}}}}
	if Edition == "commercial" {
		c.Classification.Coding = []string{"iban", "card", "social_id"}
	} else {
		// Community has no usage sensitivity: nothing labels an event sensitive.
		c.Classification = ClassificationConfig{[]string{}, []string{}, []string{}}
	}
	// Signed updates are on by default in both editions: a fleet that receives no
	// security fix is the worse default, and the delivery chain is verified
	// independently (an unconfigured chain simply has nothing to offer). The console
	// hides the Operations section unless MILVAGO_DEBUG is set, so this default is what
	// an ordinary deployment runs with, and turning it off stays a deliberate act.
	c.Operations.Updates.Enabled = true
	for _, s := range catalog {
		s.Mode = "observe"
		s.Enabled = true
		c.Services = append(c.Services, s)
	}
	return c
}

// shadowCapabilities tells the console what this edition may configure. Community
// keeps the browser collection core: no per-model control, no built-in masking
// patterns (custom regular expressions only) and no usage sensitivity.
func shadowCapabilities() map[string]bool {
	commercial := Edition == "commercial"
	return map[string]bool{"model_access_browser": commercial, "model_access_native": commercial, "browser": true, "native": commercial, "organization_inheritance": false, "content_storage": true, "device_overrides": true, "group_overrides": true, "local_privacy": true, "local_privacy_patterns": commercial, "usage_sensitivity": commercial, "file_names": true, "signed_updates": false}
}
func validateSet(v, allowed []string) bool {
	seen := map[string]bool{}
	for _, s := range v {
		if !slices.Contains(allowed, s) || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}
func validateShadow(c ShadowConfig) error {
	if e := validateModelAccess(c.ModelAccess); e != nil {
		return e
	}
	if Edition != "commercial" {
		// Community keeps the browser collection core only: no per-model control,
		// no built-in masking patterns (custom regular expressions stay), and no
		// usage sensitivity. The console hides them; the server is the authority.
		if len(c.ModelAccess) > 0 {
			return apiError{409, "capability_unavailable", "Per-model control requires the Enterprise edition."}
		}
		if len(c.Privacy.Types) > 0 {
			return apiError{409, "capability_unavailable", "Built-in masking patterns require the Enterprise edition; define custom masking rules instead."}
		}
		if len(c.Classification.Browser) > 0 || len(c.Classification.Coding) > 0 || len(c.Classification.MedicalTerms) > 0 {
			return apiError{409, "capability_unavailable", "Usage sensitivity requires the Enterprise edition."}
		}
	}
	if !slices.Contains([]string{"manual", "automatic", "network"}, c.Enrollment.Approval) || len(c.Enrollment.CIDRs)+len(c.Enrollment.Rules) > 50 {
		return bad("Invalid approval mode or networks.")
	}
	for _, s := range c.Enrollment.CIDRs {
		if _, _, e := net.ParseCIDR(s); e != nil {
			return bad("Networks must be CIDR ranges.")
		}
	}
	for _, rule := range c.Enrollment.Rules {
		if _, _, e := net.ParseCIDR(rule.CIDR); e != nil {
			return bad("Every approval rule needs a CIDR network; a domain alone never approves a device.")
		}
		if rule.Domain != "" && (len(rule.Domain) > 253 || !machineDomainPattern.MatchString(rule.Domain)) {
			return bad("A rule domain is a DNS name (Active Directory or realm) or an Entra tenant ID.")
		}
	}
	if c.Enrollment.Approval == "network" && len(c.Enrollment.CIDRs)+len(c.Enrollment.Rules) == 0 {
		return bad("Network approval requires at least one network.")
	}
	if c.Collection.ContentRetentionDays < 1 || c.Collection.ContentRetentionDays > 30 {
		return bad("Content retention must be between 1 and 30 days.")
	}
	if len(c.Services) < 1 || len(c.Services) > 128 {
		return bad("Invalid catalogue services.")
	}
	seen := map[string]bool{}
	for _, s := range c.Services {
		if !detectionID.MatchString(s.ID) || seen[s.ID] || len(s.Domains) == 0 || !slices.Contains([]string{"observe", "block", "redirect"}, s.Mode) {
			return bad("Invalid service, domains or mode.")
		}
		seen[s.ID] = true
		if s.Mode == "redirect" {
			u, e := url.Parse(s.RedirectURL)
			if e != nil || u.Host == "" || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return bad("Redirects require an HTTPS URL without credentials, query or fragment.")
			}
		}
	}
	if !slices.Contains([]string{"observe", "block"}, c.Protection.Exact) || !slices.Contains([]string{"observe", "block"}, c.Protection.Unicode) || !slices.Contains([]string{"off", "observe", "block"}, c.Protection.Fuzzy) || len(c.Protection.Message) > 500 {
		return bad("Invalid protection settings.")
	}
	for _, list := range [][]string{c.Protection.Keywords, c.Protection.Exceptions} {
		if len(list) > 200 {
			return bad("Too many keywords.")
		}
		for _, v := range list {
			if !validMetadata(v, 120) {
				return bad("Invalid keyword.")
			}
		}
	}
	if !validateSet(c.Privacy.Types, privacyTypes) || len(c.Privacy.CustomRules) > 25 {
		return bad("Invalid privacy categories or rules.")
	}
	seen = map[string]bool{}
	for _, v := range c.Privacy.CustomRules {
		if !uuidPattern.MatchString(v.ID) || seen[v.ID] || !validMetadata(v.Label, 60) || len(v.Pattern) > 200 || v.Pattern == "" {
			return bad("Invalid custom privacy rule.")
		}
		seen[v.ID] = true
		re, e := regexp.Compile(v.Pattern)
		if e != nil || re.MatchString("") {
			return bad("Custom rules must be bounded nonempty RE2-compatible expressions.")
		}
		parsed, parseErr := syntax.Parse(v.Pattern, syntax.Perl)
		if strings.Contains(v.Pattern, "(?") || parseErr != nil || nestedRepetition(parsed, false) {
			return bad("Lookaround and nested repetition are not supported.")
		}
		// Le libellé devient le marqueur inséré dans le texte masqué (`[LIBELLE]`, `[LIBELLE1]`…).
		// S'il correspond lui-même à l'expression, le marqueur serait à son tour capturé et
		// masqué : chaque passage réécrirait le précédent, sans fin. Refusé ici comme dans la
		// console (décision produit du 2026-09-16). L'essai porte sur le libellé seul, avec la
		// sensibilité à la casse de la règle — pas sur le numéro du marqueur, sans quoi toute
		// règle numérique (« NUMERO », `[0-9]+`) serait refusée alors que `[NUMERO1]` est
		// précisément la forme voulue.
		probe := re
		if v.CaseInsensitive {
			if ci, e := regexp.Compile("(?i)" + v.Pattern); e == nil {
				probe = ci
			}
		}
		if probe.MatchString(v.Label) {
			return bad("The rule label matches its own expression: the inserted placeholder would be masked again, endlessly.")
		}
	}
	if !validateSet(c.Classification.Browser, classificationTypes) || !validateSet(c.Classification.Coding, classificationTypes) || (Edition == "community" && len(c.Classification.Coding) > 0) {
		return bad("Invalid classification categories for this edition.")
	}
	if len(c.Classification.MedicalTerms) > 100 {
		return bad("At most 100 medical terms are supported.")
	}
	for _, term := range c.Classification.MedicalTerms {
		if !validMetadata(term, 60) {
			return bad("Invalid medical term.")
		}
	}
	if c.Operations.Updates.Percentage < 0 || c.Operations.Updates.Percentage > 100 || len(c.Operations.Updates.DeviceIDs) > 1000 || len(c.Operations.Updates.PausedVersions) > 100 {
		return bad("Invalid update campaign.")
	}
	for _, id := range c.Operations.Updates.DeviceIDs {
		if !uuidPattern.MatchString(id) {
			return bad("Update device IDs must be UUIDs.")
		}
	}
	for _, version := range c.Operations.Updates.PausedVersions {
		if !versionPattern.MatchString(version) {
			return bad("Paused releases must use numeric semantic versions.")
		}
	}
	// Retired settings. Both fields are kept so configurations stored before the
	// change still decode, but neither does anything, so neither may be set.
	if len(c.Operations.Destinations) > 0 {
		return apiError{409, "capability_unavailable", "Export destinations are configured in Administration → Observability."}
	}
	if c.Operations.MetricsEnabled {
		return apiError{409, "capability_unavailable", "Metrics are always available; a deployment closes them with MILVAGO_SHADOW_METRICS."}
	}
	return nil
}

// retiredOperations blanks the operations settings that no longer exist, so no
// response suggests they still work: exports moved to Administration →
// Observability, and the metrics route is governed by MILVAGO_SHADOW_METRICS.
func retiredOperations(c *ShadowConfig) {
	c.Operations.Destinations = []DestinationConfig{}
	c.Operations.MetricsEnabled = false
}
func nestedRepetition(r *syntax.Regexp, repeated bool) bool {
	if r == nil {
		return false
	}
	variable := r.Op == syntax.OpStar || r.Op == syntax.OpPlus || r.Op == syntax.OpQuest || (r.Op == syntax.OpRepeat && r.Min != r.Max)
	if variable && repeated {
		return true
	}
	for _, child := range r.Sub {
		if nestedRepetition(child, repeated || variable) {
			return true
		}
	}
	return false
}
func overlayShadow(base ShadowConfig, sections map[string]json.RawMessage) (ShadowConfig, error) {
	raw, _ := json.Marshal(base)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(raw, &m)
	for k, v := range sections {
		if k == "discovery" {
			continue
		} // Derived exclusively from effective privacy settings.
		if !slices.Contains(shadowSections, k) {
			return base, bad("Unknown configuration section.")
		}
		if string(v) != "null" {
			m[k] = v
		}
	}
	raw, _ = json.Marshal(m)
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&base); e != nil {
		return base, bad("Invalid configuration fields.")
	}
	if base.Classification.MedicalTerms == nil {
		base.Classification.MedicalTerms = defaultMedicalTerms()
	}
	if base.ModelAccess == nil {
		base.ModelAccess = []ModelAccessRule{}
	}
	for i := range base.ModelAccess {
		if base.ModelAccess[i].Models == nil {
			base.ModelAccess[i].Models = []string{}
		}
	}
	return base, nil
}
func copyShadowSection(dst *ShadowConfig, src ShadowConfig, section string) {
	switch section {
	case "model_access":
		dst.ModelAccess = src.ModelAccess
	case "enrollment":
		dst.Enrollment = src.Enrollment
	case "collection":
		dst.Collection = src.Collection
	case "services":
		dst.Services = src.Services
	case "protection":
		dst.Protection = src.Protection
	case "privacy":
		dst.Privacy = src.Privacy
	case "classification":
		dst.Classification = src.Classification
	case "operations":
		dst.Operations = src.Operations
		retiredOperations(dst)
	}
}
func (a *App) readShadow(ctx context.Context, tx pgx.Tx, org string, depth int) (ShadowSettings, error) {
	out := ShadowSettings{Revision: 1, Config: defaultShadowConfig(), InheritSections: []string{}, InheritedFrom: map[string]InheritedFrom{}, Capabilities: shadowCapabilities(), ModelCatalog: []ModelCatalogEntry{}}
	if Edition == "commercial" {
		out.ModelCatalog = modelCatalog()
	}
	// Both editions ship a signed agent; availability depends on the delivery chain.
	out.Capabilities["signed_updates"] = a.updatesAvailable()
	if depth > 20 {
		return out, bad("Organization ancestry exceeds supported depth.")
	}
	var raw map[string]json.RawMessage
	e := tx.QueryRow(ctx, `SELECT revision,configuration,inherit_sections FROM shadow_settings WHERE organization_id=$1`, org).Scan(&out.Revision, &raw, &out.InheritSections)
	if e != nil && e != pgx.ErrNoRows {
		return out, e
	}
	if raw != nil {
		out.Config, e = overlayShadow(out.Config, raw)
		if e != nil {
			return out, e
		}
	}
	if Edition == "commercial" {
		var parent *string
		var name string
		if e = tx.QueryRow(ctx, `SELECT parent_id FROM organizations WHERE id=$1`, org).Scan(&parent); e != nil {
			return out, e
		}
		out.Capabilities["organization_inheritance"] = parent != nil
		if parent != nil && len(out.InheritSections) > 0 {
			p, parentName, e := a.readParentShadow(ctx, tx, org, *parent, depth+1)
			if e != nil {
				return out, e
			}
			name = parentName
			for _, s := range out.InheritSections {
				copyShadowSection(&out.Config, p.Config, s)
				out.InheritedFrom[s] = InheritedFrom{OrganizationID: *parent, Name: name}
				if origin, ok := p.InheritedFrom[s]; ok {
					out.InheritedFrom[s] = origin
				}
			}
			out.Revision = max(out.Revision, p.Revision)
		}
	}
	if depth == 0 {
		if e = a.enrichDetectionPolicy(ctx, tx, org, &out); e != nil {
			return out, e
		}
	}
	return out, nil
}

// Resolve ancestors on the caller's connection: borrowing another pooled
// connection while retaining this one can starve the entire pool under load.
// Each recursive visit restores its caller's tenant, including on failure.
func (a *App) readParentShadow(ctx context.Context, tx pgx.Tx, org, parent string, depth int) (out ShadowSettings, name string, err error) {
	if _, err = tx.Exec(ctx, sqlSetOrganizationContext, parent); err != nil {
		return
	}
	defer func() {
		_, restoreErr := tx.Exec(ctx, sqlSetOrganizationContext, org)
		if err == nil {
			err = restoreErr
		}
	}()
	if out, err = a.readShadow(ctx, tx, parent, depth); err != nil {
		return
	}
	err = tx.QueryRow(ctx, `SELECT name FROM organizations WHERE id=$1`, parent).Scan(&name)
	return
}

// overrideSections are the browser-policy sections a device group or a single
// device may override. Enrollment and operations stay with the organization.
var overrideSections = []string{"collection", "services", "protection", "privacy", "classification", "model_access"}

// inheritedSections lists the override sections absent from a stored override:
// the ones still taken from the level above.
func inheritedSections(raw map[string]json.RawMessage) []string {
	out := []string{}
	for _, section := range overrideSections {
		if _, ok := raw[section]; !ok {
			out = append(out, section)
		}
	}
	return out
}

// groupOverlay applies one group's stored override to base and records the
// group as the provenance of every section it sets. It returns the override's
// revision (0 when the group has none), the stored sections, and pgx.ErrNoRows
// when the group does not exist in the current organization.
func (a *App) groupOverlay(ctx context.Context, tx pgx.Tx, group string, base *ShadowSettings) (int64, map[string]json.RawMessage, error) {
	var name string
	var rev int64
	var raw map[string]json.RawMessage
	if e := tx.QueryRow(ctx, `SELECT g.name,COALESCE(o.revision,0),o.configuration FROM device_groups g LEFT JOIN shadow_group_overrides o ON o.organization_id=g.organization_id AND o.group_id=g.id WHERE g.id=$1`, group).Scan(&name, &rev, &raw); e != nil {
		return 0, nil, e
	}
	if raw == nil {
		return 0, nil, nil
	}
	next, e := overlayShadow(base.Config, raw)
	if e != nil {
		return 0, nil, e
	}
	base.Config = next
	for section := range raw {
		base.InheritedFrom[section] = InheritedFrom{GroupID: group, Name: name}
	}
	return rev, raw, nil
}

// groupShadow is the organization policy with one group's override applied: what
// a member device inherits before its own derogation, and what the group page
// edits. Its revision is the organization's plus the override's.
func (a *App) groupShadow(ctx context.Context, tx pgx.Tx, org, group string) (ShadowSettings, error) {
	out, e := a.readShadow(ctx, tx, org, 0)
	if e != nil {
		return out, e
	}
	rev, raw, e := a.groupOverlay(ctx, tx, group, &out)
	if e != nil {
		return out, e
	}
	out.InheritSections = inheritedSections(raw)
	out.Revision += rev
	return out, nil
}

// deviceBase is the policy a device inherits before its own override: the
// organization's, with its group's override applied when it belongs to one. The
// second value is the group term of the device's effective revision.
//
// That term is max(group override revision, devices.group_revision), not their
// sum. The agent refuses any policy whose revision is lower than the one it
// holds (anti-rollback), so a device moved from a recently saved group to an
// older one must not see its revision fall. Every change to the group side --
// saving the group's policy, assigning, detaching, deleting the group -- draws a
// fresh value from shadow_revision into one of the two operands, so their max
// only ever grows. A device that never joined a group contributes 0 and keeps
// exactly the revision it had before groups existed.
func (a *App) deviceBase(ctx context.Context, tx pgx.Tx, org, device string) (ShadowSettings, int64, error) {
	out, e := a.readShadow(ctx, tx, org, 0)
	if e != nil {
		return out, 0, e
	}
	var group *string
	var assigned int64
	e = tx.QueryRow(ctx, `SELECT group_id,group_revision FROM devices WHERE id=$1`, device).Scan(&group, &assigned)
	if e == pgx.ErrNoRows {
		return out, 0, nil
	}
	if e != nil {
		return out, 0, e
	}
	if group != nil {
		rev, _, e := a.groupOverlay(ctx, tx, *group, &out)
		if e != nil {
			return out, 0, e
		}
		assigned = max(assigned, rev)
	}
	return out, assigned, nil
}

// effectiveShadow resolves the policy one device receives: organization (with
// its parent's inherited sections), then its group's override, then its own.
func (a *App) effectiveShadow(ctx context.Context, tx pgx.Tx, org, device string) (ShadowSettings, error) {
	if device == "" {
		return a.readShadow(ctx, tx, org, 0)
	}
	out, groupTerm, e := a.deviceBase(ctx, tx, org, device)
	if e != nil {
		return out, e
	}
	out.Revision += groupTerm
	var raw map[string]json.RawMessage
	out.InheritSections = inheritedSections(nil)
	var rev int64
	e = tx.QueryRow(ctx, `SELECT revision,configuration FROM shadow_device_overrides WHERE organization_id=$1 AND device_id=$2`, org, device).Scan(&rev, &raw)
	if e == pgx.ErrNoRows {
		return out, nil
	}
	if e != nil {
		return out, e
	}
	out.Config, e = overlayShadow(out.Config, raw)
	out.InheritSections = inheritedSections(raw)
	out.Revision += rev
	return out, e
}
func (a *App) shadowSettings(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	out, e := a.readShadow(r.Context(), tx, s.OrganizationID, 0)
	if e != nil {
		return e
	}
	retiredOperations(&out.Config)
	reply(w, 200, out)
	return nil
}
func (a *App) putShadowSettings(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var body struct {
		Revision        int64        `json:"revision"`
		Config          ShadowConfig `json:"config"`
		InheritSections []string     `json:"inherit_sections"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if !validateSet(body.InheritSections, shadowSections) || (Edition == "community" && len(body.InheritSections) > 0) {
		return bad("Organization inheritance is unavailable or invalid.")
	}
	if len(body.InheritSections) > 0 {
		var parent *string
		if e := tx.QueryRow(r.Context(), `SELECT parent_id FROM organizations WHERE id=$1`, s.OrganizationID).Scan(&parent); e != nil {
			return e
		}
		if parent == nil {
			return bad("This organization has no parent.")
		}
	}
	if body.Config.ModelAccess == nil {
		body.Config.ModelAccess = []ModelAccessRule{}
	}
	for i := range body.Config.ModelAccess {
		if body.Config.ModelAccess[i].Models == nil {
			body.Config.ModelAccess[i].Models = []string{}
		}
	}
	if e := a.validateCatalogPolicy(r.Context(), tx, body.Config); e != nil {
		return e
	}
	if e := validateShadow(body.Config); e != nil {
		return e
	}
	// No check against the delivery chain here, deliberately. `enabled` is an
	// intent; whether a signed release can actually be served is a capability, and
	// the two are resolved separately -- applicableUpdate requires *both*
	// (shadow_update.go), so an intent stored without a chain delivers nothing.
	//
	// Refusing the save instead would be actively harmful now that Enterprise
	// defaults the channel on: a deployment with no release directory configured
	// could not save *any* Shadow AI setting, because every round-trip of its own
	// default configuration would come back 409. The console already greys the
	// control and says the chain is not operational.
	if _, e := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1, 71))`, s.OrganizationID); e != nil {
		return e
	}
	if _, e := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(7069202)`); e != nil {
		return e
	}
	old, e := a.readShadow(r.Context(), tx, s.OrganizationID, 0)
	if e != nil {
		return e
	}
	if old.Revision != body.Revision {
		return apiError{409, "revision_conflict", "Configuration changed; reload before saving."}
	}
	raw, _ := json.Marshal(body.Config)
	inherit, _ := json.Marshal(body.InheritSections)
	if _, e = tx.Exec(r.Context(), `INSERT INTO shadow_settings(organization_id,configuration,inherit_sections) VALUES($1,$2,$3) ON CONFLICT(organization_id) DO UPDATE SET configuration=excluded.configuration,inherit_sections=excluded.inherit_sections,revision=nextval('shadow_revision'),updated_at=now()`, s.OrganizationID, raw, inherit); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, "shadow.settings.update", s.OrganizationID); e != nil {
		return e
	}
	out, e := a.readShadow(r.Context(), tx, s.OrganizationID, 0)
	if e != nil {
		return e
	}
	if out.Config.Collection.StoreContent && !old.Config.Collection.StoreContent {
		if e = a.requireFreshPerson(r, tx, s); e != nil {
			return e
		}
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	retiredOperations(&out.Config)
	reply(w, 200, out)
	return nil
}
func (a *App) deviceShadow(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if !uuidPattern.MatchString(r.PathValue("id")) {
		return bad("Invalid device ID.")
	}
	var found bool
	if e := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM devices WHERE id=$1)`, r.PathValue("id")).Scan(&found); e != nil {
		return e
	}
	if !found {
		return apiError{404, "not_found", "Device not found."}
	}
	out, e := a.effectiveShadow(r.Context(), tx, s.OrganizationID, r.PathValue("id"))
	if e != nil {
		return e
	}
	retiredOperations(&out.Config)
	reply(w, 200, out)
	return nil
}

// shadowScope is one row a browser-policy override is stored against: a device
// or a device group. The three readers give putScopedShadow what differs between
// the two; everything else -- section rules, revision check, validation, the MFA
// gate on content collection -- is the same and lives once.
type shadowScope struct {
	// lock verifies the row exists in the current organization and takes its row
	// lock; it answers the scope's own 404.
	lock func() error
	// base is the configuration the override applies to (the level above).
	base func() (ShadowSettings, error)
	// effective is the resolved policy with the override applied.
	effective func() (ShadowSettings, error)
	// store writes the cleaned override sections.
	store  func(raw []byte) error
	action string
	target string
}

func (a *App) putScopedShadow(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session, scope shadowScope) error {
	var body struct {
		Revision        int64                      `json:"revision"`
		Config          map[string]json.RawMessage `json:"config"`
		InheritSections []string                   `json:"inherit_sections"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	// The policy barrier before the row: ingestion takes them in that order, and the
	// reverse order here deadlocked with an event batch from the same device.
	if _, e := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(7069202)`); e != nil {
		return e
	}
	if e := scope.lock(); e != nil {
		return e
	}
	if !validateSet(body.InheritSections, overrideSections) {
		return bad("Invalid inheritance.")
	}
	if body.Config == nil {
		body.Config = map[string]json.RawMessage{}
	}
	for k, v := range body.Config {
		if !slices.Contains(overrideSections, k) {
			return bad("Only browser protection sections can be overridden.")
		}
		if string(v) == "null" || slices.Contains(body.InheritSections, k) {
			delete(body.Config, k)
		}
	}
	old, e := scope.effective()
	if e != nil {
		return e
	}
	if old.Revision != body.Revision {
		return apiError{409, "revision_conflict", "Configuration changed; reload before saving."}
	}
	base, e := scope.base()
	if e != nil {
		return e
	}
	next, e := overlayShadow(base.Config, body.Config)
	if e != nil {
		return e
	}
	if e = a.validateCatalogPolicy(r.Context(), tx, next); e != nil {
		return e
	}
	if e = validateShadow(next); e != nil {
		return e
	}
	if next.Collection.StoreContent && !old.Config.Collection.StoreContent {
		if e = a.requireFreshPerson(r, tx, s); e != nil {
			return e
		}
	}
	raw, _ := json.Marshal(body.Config)
	if e = scope.store(raw); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, scope.action, scope.target); e != nil {
		return e
	}
	out, e := scope.effective()
	if e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	retiredOperations(&out.Config)
	reply(w, 200, out)
	return nil
}

func (a *App) putDeviceShadow(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad("Invalid device ID.")
	}
	ctx, org := r.Context(), s.OrganizationID
	return a.putScopedShadow(w, r, tx, s, shadowScope{
		lock: func() error {
			var exists string
			if e := tx.QueryRow(ctx, `SELECT id FROM devices WHERE id=$1 FOR UPDATE`, id).Scan(&exists); e != nil {
				return apiError{404, "not_found", "Device not found."}
			}
			return nil
		},
		base: func() (ShadowSettings, error) {
			out, _, e := a.deviceBase(ctx, tx, org, id)
			return out, e
		},
		effective: func() (ShadowSettings, error) { return a.effectiveShadow(ctx, tx, org, id) },
		store: func(raw []byte) error {
			_, e := tx.Exec(ctx, `INSERT INTO shadow_device_overrides(organization_id,device_id,configuration) VALUES($1,$2,$3) ON CONFLICT(organization_id,device_id) DO UPDATE SET configuration=excluded.configuration,revision=nextval('shadow_revision')`, org, id, raw)
			return e
		},
		action: "shadow.device.update", target: id,
	})
}

func (a *App) groupShadowSettings(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad("Invalid group ID.")
	}
	out, e := a.groupShadow(r.Context(), tx, s.OrganizationID, id)
	if e == pgx.ErrNoRows {
		return groupNotFound()
	}
	if e != nil {
		return e
	}
	retiredOperations(&out.Config)
	reply(w, 200, out)
	return nil
}

func (a *App) putGroupShadow(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad("Invalid group ID.")
	}
	ctx, org := r.Context(), s.OrganizationID
	return a.putScopedShadow(w, r, tx, s, shadowScope{
		lock: func() error {
			var exists string
			if e := tx.QueryRow(ctx, `SELECT id FROM device_groups WHERE id=$1 FOR UPDATE`, id).Scan(&exists); e != nil {
				return groupNotFound()
			}
			return nil
		},
		base:      func() (ShadowSettings, error) { return a.readShadow(ctx, tx, org, 0) },
		effective: func() (ShadowSettings, error) { return a.groupShadow(ctx, tx, org, id) },
		store: func(raw []byte) error {
			_, e := tx.Exec(ctx, `INSERT INTO shadow_group_overrides(organization_id,group_id,configuration) VALUES($1,$2,$3) ON CONFLICT(organization_id,group_id) DO UPDATE SET configuration=excluded.configuration,revision=nextval('shadow_revision')`, org, id, raw)
			return e
		},
		action: "shadow.group.update", target: id,
	})
}

// requireFreshPerson guards changes as sensitive as the privacy settings, made on a
// route that keys may otherwise use: turning prompt retention on, shortening event
// retention. A second factor verified in the last minutes, not the one from a sign-in
// up to eight hours old, and never a key or a token, which have no second factor to
// present (audit of 2026-09-24).
func (a *App) requireFreshPerson(r *http.Request, tx pgx.Tx, s *Session) error {
	if s.pinned() {
		return apiError{403, "session_required", "This change requires a signed-in person."}
	}
	return a.requireFreshMFA(r, tx, s)
}
