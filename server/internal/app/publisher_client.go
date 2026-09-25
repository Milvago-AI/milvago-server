package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	sqlDeletePublisherOutbox = "DELETE FROM publisher_client_outbox"
)

type publisherHealth struct {
	Provider         string   `json:"provider"`
	CatalogRevision  uint64   `json:"catalog_revision"`
	State            string   `json:"state"`
	DOMCoverageRatio *float64 `json:"dom_coverage_ratio,omitempty"`
}
type publisherFleet struct {
	Enrolled  uint64 `json:"enrolled"`
	Active30d uint64 `json:"active_30d"`
}
type publisherBatch struct {
	BatchID        string            `json:"batch_id"`
	SentAt         time.Time         `json:"sent_at"`
	EngineVersion  string            `json:"engine_version"`
	ProviderHealth []publisherHealth `json:"provider_health"`
	Fleet          *publisherFleet   `json:"fleet,omitempty"`
}
type publisherConsent struct {
	Organization  string
	Revision      int64
	Health, Fleet bool
}
type publisherHeader struct {
	Kind      string    `json:"kind"`
	Schema    int       `json:"schema"`
	Revision  int64     `json:"revision"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	MinEngine struct {
		Extension string `json:"extension"`
		Bridge    string `json:"bridge"`
	} `json:"min_engine"`
	ContentHash string `json:"content_hash"`
	Content     string `json:"content"`
}
type publisherEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func initializePublisherClient(ctx context.Context, tx pgx.Tx, role string) error {
	_, e := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS publisher_client_state (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),instance_id text NOT NULL DEFAULT ('i-'||replace(gen_random_uuid()::text,'-','')),
 last_telemetry_day date,last_success timestamptz,last_error text NOT NULL DEFAULT '',publisher_revision bigint NOT NULL DEFAULT 0,
 publisher_hash text NOT NULL DEFAULT '',last_catalog_attempt timestamptz,configuration_key text NOT NULL DEFAULT '');
 INSERT INTO publisher_client_state(singleton) VALUES(true) ON CONFLICT DO NOTHING;
 CREATE TABLE IF NOT EXISTS publisher_client_outbox (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),batch_id uuid NOT NULL,payload bytea NOT NULL,consents jsonb NOT NULL,
 configuration_key text NOT NULL,next_attempt timestamptz NOT NULL DEFAULT now(),attempts integer NOT NULL DEFAULT 0,created_at timestamptz NOT NULL DEFAULT now());
 GRANT SELECT,INSERT,UPDATE,DELETE ON publisher_client_state,publisher_client_outbox TO `+role)
	return e
}
func publisherOrigin(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("invalid publisher origin")
	}
	local := slices.Contains([]string{"localhost", "127.0.0.1", "::1"}, u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, errors.New("publisher requires HTTPS")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && blockedCollectorIP(ip) {
		return nil, errors.New("publisher address prohibited")
	}
	return u, nil
}
func (a *App) publisherClient() (*http.Client, *url.URL, error) {
	u, e := publisherOrigin(a.config.PublisherURL)
	if e != nil {
		return nil, nil, e
	}
	tr := &http.Transport{Proxy: nil, DialContext: collectorDial, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: a.config.CollectorRoots}, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, u, nil
}
func decodePublisherEnvelope(raw []byte, key ed25519.PublicKey, minimum int64, oldHash string, now time.Time) (publisherHeader, []byte, error) {
	var env publisherEnvelope
	var h publisherHeader
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 1400*1024 || len(key) != ed25519.PublicKeySize || d.Decode(&env) != nil || d.Decode(new(any)) != io.EOF {
		return h, nil, errors.New("invalid publisher envelope")
	}
	payload, e := base64.StdEncoding.DecodeString(env.Payload)
	if e != nil || len(payload) > 1024*1024 {
		return h, nil, errors.New("invalid publisher payload")
	}
	sig, e := base64.StdEncoding.DecodeString(env.Signature)
	if e != nil || !ed25519.Verify(key, payload, sig) {
		return h, nil, errors.New("publisher signature refused")
	}
	d = json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if d.Decode(&h) != nil || d.Decode(new(any)) != io.EOF || h.Kind != "detection_catalog" || h.Schema != 1 || h.Revision < 1 || h.Revision < minimum || !h.ExpiresAt.After(now) || h.IssuedAt.After(now.Add(time.Minute)) || !h.ExpiresAt.After(h.IssuedAt) || h.ExpiresAt.Sub(h.IssuedAt) > 7*24*time.Hour {
		return h, nil, errors.New("publisher authority invalid")
	}
	for _, v := range []string{h.MinEngine.Extension, h.MinEngine.Bridge} {
		if !versionPattern.MatchString(v) || versionNewer(v, "0.5.0") {
			return h, nil, errors.New("publisher engine incompatible")
		}
	}
	content, e := base64.StdEncoding.DecodeString(h.Content)
	if e != nil {
		return h, nil, errors.New("invalid publisher content")
	}
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	if digest != h.ContentHash || (h.Revision == minimum && oldHash != "" && oldHash != digest) {
		return h, nil, errors.New("publisher content changed")
	}
	if _, e = decodeDetection(content); e != nil {
		return h, nil, e
	}
	return h, content, nil
}
func (a *App) publisherRequest(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	client, origin, e := a.publisherClient()
	if e != nil {
		return nil, e
	}
	target := origin.ResolveReference(&url.URL{Path: path})
	req, e := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+a.config.PublisherCredential)
	req.Header.Set("Content-Type", "application/json")
	res, e := client.Do(req)
	if e != nil {
		return nil, errors.New("publisher unavailable")
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, 1400*1024+1))
	if e != nil || len(raw) > 1400*1024 {
		return nil, errors.New("publisher response too large")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, errors.New("publisher refused request")
	}
	return raw, nil
}
func compactJSON(raw []byte) []byte {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	out, _ := json.Marshal(v)
	return out
}

type publisherSums struct{ devices, network, dom, navigations, previous int64 }
type publisherHealthKey struct {
	provider string
	revision int64
}

type publisherSnapshotState struct {
	batch    *publisherBatch
	consents *[]publisherConsent
	auto     *bool
	root     string
	known    map[string]bool
	counts   map[publisherHealthKey]*publisherSums
	dayEnd   time.Time
}

func (a *App) publisherSnapshotOrganization(ctx context.Context, tx pgx.Tx, org string, state *publisherSnapshotState) error {
	var e error
	root := state.root
	if _, e = tx.Exec(ctx, "SELECT set_config('milvago.organization_id',$1,true)", org); e != nil {
		return e
	}
	var ownRaw []byte
	var since time.Time
	e = tx.QueryRow(ctx, "SELECT configuration,updated_at FROM privacy_settings WHERE organization_id=$1 FOR SHARE", org).Scan(&ownRaw, &since)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	cfg, e := a.readPrivacy(ctx, tx, org)
	if e != nil {
		return e
	}
	if org == root {
		*state.auto = cfg.Config.AutoCatalog
	}
	if !cfg.Config.ShareHealth && !cfg.Config.ShareFleet {
		return nil
	}
	*state.consents = append(*state.consents, publisherConsent{org, cfg.Revision, cfg.Config.ShareHealth, cfg.Config.ShareFleet})

	if cfg.Config.ShareFleet {
		if e := state.publisherAddFleet(ctx, tx); e != nil {
			return e
		}
	}
	if !cfg.Config.ShareHealth {
		return nil
	}
	return state.publisherAddHealth(ctx, tx, since)
}

func (state *publisherSnapshotState) publisherAddFleet(ctx context.Context, tx pgx.Tx) error {
	if state.batch.Fleet == nil {
		state.batch.Fleet = &publisherFleet{}
	}
	var total, active uint64
	if e := tx.QueryRow(ctx, "SELECT count(*),count(*) FILTER(WHERE last_seen>=now()-interval '30 days') FROM devices WHERE status<>'revoked'").Scan(&total, &active); e != nil {
		return e
	}
	state.batch.Fleet.Enrolled += total
	state.batch.Fleet.Active30d += active
	return nil
}

func (state *publisherSnapshotState) publisherAddHealth(ctx context.Context, tx pgx.Tx, since time.Time) error {
	known, counts, dayEnd := state.known, state.counts, state.dayEnd
	var e error
	data, e := tx.Query(ctx, `SELECT c->>'provider',(payload->>'catalog_revision')::bigint,
 count(DISTINCT device_id) FILTER(WHERE (payload->>'window_end')::timestamptz >= $3 AND coalesce((c->>'navigations')::bigint,0)>0),
 coalesce(sum((c->>'prompts_network')::bigint) FILTER(WHERE (payload->>'window_end')::timestamptz >= $3),0),
 coalesce(sum((c->>'prompts_dom')::bigint) FILTER(WHERE (payload->>'window_end')::timestamptz >= $3),0),
 coalesce(sum((c->>'navigations')::bigint) FILTER(WHERE (payload->>'window_end')::timestamptz >= $3),0),
 coalesce(sum((c->>'prompts_network')::bigint+(c->>'prompts_dom')::bigint) FILTER(WHERE (payload->>'window_end')::timestamptz < $3),0)
 FROM detector_health CROSS JOIN LATERAL jsonb_array_elements(payload->'providers') c
 WHERE (payload->>'window_end')::timestamptz < $1 AND (payload->>'window_end')::timestamptz >= $4
 AND (payload->>'window_start')::timestamptz >= $2
 GROUP BY c->>'provider',(payload->>'catalog_revision')::bigint`, dayEnd, since, dayEnd.Add(-24*time.Hour), dayEnd.Add(-8*24*time.Hour))
	if e != nil {
		return e
	}
	for data.Next() {
		var id string
		var revision int64
		var v publisherSums
		if e = data.Scan(&id, &revision, &v.devices, &v.network, &v.dom, &v.navigations, &v.previous); e != nil {
			data.Close()
			return e
		}
		if !known[id] {
			continue
		}
		key := publisherHealthKey{id, revision}
		if counts[key] == nil {
			counts[key] = &publisherSums{}
		}
		n := counts[key]
		n.devices += v.devices
		n.network += v.network
		n.dom += v.dom
		n.navigations += v.navigations
		n.previous += v.previous
	}
	data.Close()
	if e = data.Err(); e != nil {
		return e
	}
	return nil
}

func publisherOrganizationIDs(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, e := tx.Query(ctx, "SELECT id FROM organizations ORDER BY id")
	if e != nil {
		return nil, e
	}
	orgs := []string{}
	for rows.Next() {
		var org string
		if e = rows.Scan(&org); e != nil {
			rows.Close()
			return nil, e
		}
		orgs = append(orgs, org)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return nil, e
	}
	return orgs, nil
}

func publisherKnownProviders() (map[string]bool, error) {
	known := map[string]bool{}
	var factory DetectionContent
	if e := json.Unmarshal(detectionFactory, &factory); e != nil {
		return nil, e
	}
	restrictEditionProviders(&factory)
	for _, p := range factory.Providers {
		known[p.ID] = true
	}
	return known, nil
}

func (state *publisherSnapshotState) finishHealth() {
	batch, counts := state.batch, state.counts
	for key, n := range counts {
		var ratio *float64
		if n.network > 0 {
			v := min(1, float64(n.dom)/float64(n.network))
			ratio = &v
		}
		// The shared verdict aggregates every consenting organization, so it uses the
		// instance defaults for the thresholds rather than one organization's own.
		defaults := defaultPrivacy()
		state := detectorState(detectorSample{Devices: n.devices, Navigations: n.navigations, Network: n.network, DOM: n.dom, Previous: n.previous}, defaults.HealthMinDevices, defaults.HealthDOMRatio)
		batch.ProviderHealth = append(batch.ProviderHealth, publisherHealth{key.provider, uint64(max(0, key.revision)), state, ratio})
	}
	slices.SortFunc(batch.ProviderHealth, func(a, b publisherHealth) int {
		if order := strings.Compare(a.Provider, b.Provider); order != 0 {
			return order
		}
		if a.CatalogRevision < b.CatalogRevision {
			return -1
		}
		if a.CatalogRevision > b.CatalogRevision {
			return 1
		}
		return 0
	})
}

// Consent rows remain locked through delivery: a completed opt-out cannot race
// a send assembled from an older consent. Organization IDs stay local.
func (a *App) publisherSnapshot(ctx context.Context, tx pgx.Tx) (publisherBatch, []publisherConsent, string, bool, error) {
	batch := publisherBatch{SentAt: time.Now().UTC(), EngineVersion: "0.5.0", ProviderHealth: []publisherHealth{}}
	var root string
	if e := tx.QueryRow(ctx, "SELECT organization_id FROM app_config").Scan(&root); e != nil {
		return batch, nil, "", false, e
	}
	orgs, e := publisherOrganizationIDs(ctx, tx)
	if e != nil {
		return batch, nil, "", false, e
	}
	known, e := publisherKnownProviders()
	if e != nil {
		return batch, nil, "", false, e
	}
	counts := map[publisherHealthKey]*publisherSums{}
	dayEnd := batch.SentAt.Truncate(24 * time.Hour)
	consents := []publisherConsent{}
	auto := false
	state := publisherSnapshotState{batch: &batch, consents: &consents, auto: &auto, root: root, known: known, counts: counts, dayEnd: dayEnd}
	for _, org := range orgs {
		if e := a.publisherSnapshotOrganization(ctx, tx, org, &state); e != nil {
			return batch, nil, "", false, e
		}
	}
	state.finishHealth()
	return batch, consents, root, auto, nil
}
func (a *App) maintainPublisher(ctx context.Context) {
	if a.config.PublisherURL == "" || a.config.PublisherCredential == "" {
		return
	}
	job, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if a.publisherPass(job) != nil {
		a.log.Error("publisher maintenance failed")
	}
}
func validatePublisherEdition(edition string, content []byte) error {
	if edition != "community" {
		return nil
	}
	catalog, err := decodeDetection(content)
	if err != nil || len(catalog.NativeTools) != 0 || len(catalog.Providers) != 2 {
		return errors.New("publisher Community catalogue contains unsupported capture")
	}
	seen := map[string]bool{}
	for _, provider := range catalog.Providers {
		if provider.ID != "chatgpt" && provider.ID != "claude" || seen[provider.ID] {
			return errors.New("publisher Community catalogue contains unsupported capture")
		}
		seen[provider.ID] = true
	}
	return nil
}
func (a *App) importPublisher(ctx context.Context, tx pgx.Tx, root string, revision int64, digest string) error {
	raw, e := a.publisherRequest(ctx, "GET", "/v1/detection-catalog/latest", nil)
	if e != nil {
		return e
	}
	key := a.config.PublisherPublicKey
	h, content, e := decodePublisherEnvelope(raw, ed25519.PublicKey(key), revision, digest, time.Now().UTC())
	if e != nil {
		return e
	}
	if e = validatePublisherEdition(Edition, content); e != nil {
		return e
	}
	if h.Revision == revision {
		return nil
	}
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(726403212)"); e != nil {
		return e
	}
	var env publisherEnvelope
	_ = json.Unmarshal(raw, &env)
	if _, e = tx.Exec(ctx, "INSERT INTO detection_catalogs(content,content_hash,source,publisher_signature) VALUES($1,$2,'imported',$3)", content, h.ContentHash, env.Signature); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE publisher_client_state SET publisher_revision=$1,publisher_hash=$2", h.Revision, h.ContentHash); e != nil {
		return e
	}
	return audit(ctx, tx, root, "system", "detection.catalog.import", "instance")
}

func (a *App) publisherConfigurationKey() string {
	sum := sha256.Sum256([]byte(a.config.PublisherURL + "|" + a.config.PublisherCredential + "|" + base64.StdEncoding.EncodeToString(a.config.PublisherPublicKey)))
	return hex.EncodeToString(sum[:])
}

func discardPublisherOutbox(ctx context.Context, tx pgx.Tx, root, reason string) error {
	tag, err := tx.Exec(ctx, sqlDeletePublisherOutbox)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	details, err := json.Marshal(map[string]any{"rows": tag.RowsAffected(), "reason": reason})
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit(organization_id,actor,action,target,details) VALUES($1,'system','publisher.outbox.discarded','instance',$2)", root, details); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE publisher_client_state SET last_error=$1", "outbox_discarded_"+reason)
	return err
}

type publisherPassState struct {
	day                      *time.Time
	revision                 int64
	digest, configurationKey string
	catalogDue               bool
	batch                    publisherBatch
	consents                 []publisherConsent
	root                     string
	auto                     bool
	key                      string
	pending                  []byte
	due                      bool
	attempts                 int
	snapshot                 []byte
	today                    time.Time
}

func (a *App) publisherPass(ctx context.Context) error {
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var locked bool
	if e = tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock(726403214)").Scan(&locked); e != nil || !locked {
		return e
	}
	state, e := a.publisherPassSnapshot(ctx, tx)
	if e != nil {
		return e
	}
	if e = a.publisherPassCatalog(ctx, tx, &state); e != nil {
		return e
	}
	if e = publisherReadOutbox(ctx, tx, &state); e != nil {
		return e
	}
	if len(state.consents) == 0 {
		if e = discardPublisherOutbox(ctx, tx, state.root, "consent_changed"); e != nil {
			return e
		}
		return tx.Commit(ctx)
	}
	if e = publisherQueueOutbox(ctx, tx, &state); e != nil {
		return e
	}
	if e = a.publisherDeliverOutbox(ctx, tx, &state); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (a *App) publisherPassSnapshot(ctx context.Context, tx pgx.Tx) (publisherPassState, error) {
	var state publisherPassState
	e := tx.QueryRow(ctx, `SELECT last_telemetry_day,publisher_revision,publisher_hash,configuration_key,last_catalog_attempt IS NULL OR last_catalog_attempt<clock_timestamp()-interval '1 hour' FROM publisher_client_state WHERE singleton FOR UPDATE`).Scan(&state.day, &state.revision, &state.digest, &state.configurationKey, &state.catalogDue)
	if e != nil {
		return state, e
	}
	state.batch, state.consents, state.root, state.auto, e = a.publisherSnapshot(ctx, tx)
	if e != nil {
		return state, e
	}
	_, e = tx.Exec(ctx, "SELECT set_config('milvago.organization_id',$1,true)", state.root)
	return state, e
}

func (a *App) publisherPassCatalog(ctx context.Context, tx pgx.Tx, state *publisherPassState) error {
	state.key = a.publisherConfigurationKey()
	if state.configurationKey != state.key {
		if e := discardPublisherOutbox(ctx, tx, state.root, "configuration_changed"); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, "UPDATE publisher_client_state SET configuration_key=$1,last_catalog_attempt=NULL", state.key); e != nil {
			return e
		}
		state.catalogDue = true
	}
	if state.auto && state.catalogDue {
		importErr := a.importPublisher(ctx, tx, state.root, state.revision, state.digest)
		status := ""
		if importErr != nil {
			status = "catalog_refused"
		}
		if _, e := tx.Exec(ctx, "UPDATE publisher_client_state SET last_catalog_attempt=clock_timestamp(),last_error=$1", status); e != nil {
			return e
		}
	}
	return nil
}

func publisherReadOutbox(ctx context.Context, tx pgx.Tx, state *publisherPassState) error {
	var heldConsents []byte
	var existingKey string
	e := tx.QueryRow(ctx, "SELECT payload,consents,next_attempt<=clock_timestamp(),attempts,configuration_key FROM publisher_client_outbox WHERE singleton FOR UPDATE").Scan(&state.pending, &heldConsents, &state.due, &state.attempts, &existingKey)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	state.snapshot, _ = json.Marshal(state.consents)
	if e == nil && (existingKey != state.key || !bytes.Equal(compactJSON(heldConsents), compactJSON(state.snapshot))) {
		if e = discardPublisherOutbox(ctx, tx, state.root, "consent_changed"); e != nil {
			return e
		}
		state.pending = nil
	}
	return nil
}

func publisherQueueOutbox(ctx context.Context, tx pgx.Tx, state *publisherPassState) error {
	state.today = time.Now().UTC().Truncate(24 * time.Hour)
	if len(state.pending) == 0 && (state.day == nil || state.day.Before(state.today)) && (len(state.batch.ProviderHealth) > 0 || state.batch.Fleet != nil) {
		if e := tx.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&state.batch.BatchID); e != nil {
			return e
		}
		state.pending, _ = json.Marshal(state.batch)
		if _, e := tx.Exec(ctx, "INSERT INTO publisher_client_outbox(batch_id,payload,consents,configuration_key) VALUES($1,$2,$3,$4)", state.batch.BatchID, state.pending, state.snapshot, state.key); e != nil {
			return e
		}
		state.due = true
		state.attempts = 0
	}
	return nil
}

func (a *App) publisherDeliverOutbox(ctx context.Context, tx pgx.Tx, state *publisherPassState) error {
	if len(state.pending) == 0 || !state.due {
		return nil
	}
	var queued publisherBatch
	if e := json.Unmarshal(state.pending, &queued); e != nil {
		return e
	}
	if queued.SentAt.Before(time.Now().Add(-48 * time.Hour)) {
		return discardPublisherOutbox(ctx, tx, state.root, "expired")
	}
	_, sendErr := a.publisherRequest(ctx, "POST", "/v1/telemetry", state.pending)
	if sendErr == nil {
		if _, e := tx.Exec(ctx, sqlDeletePublisherOutbox); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, "UPDATE publisher_client_state SET last_telemetry_day=$1,last_success=clock_timestamp(),last_error=''", state.today); e != nil {
			return e
		}
	} else {
		if _, e := tx.Exec(ctx, "UPDATE publisher_client_outbox SET attempts=attempts+1,next_attempt=clock_timestamp()+$1::interval", (time.Minute * time.Duration(1<<min(state.attempts, 6))).String()); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, "UPDATE publisher_client_state SET last_error='telemetry_unavailable'"); e != nil {
			return e
		}
	}
	return nil
}
func (a *App) publisherPreview(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if !isInstanceOwner(r.Context(), tx, s) {
		return forbidden()
	}
	batch, consents, _, auto, e := a.publisherSnapshot(r.Context(), tx)
	if e != nil {
		return e
	}
	var id, status string
	var success *time.Time
	if e = tx.QueryRow(r.Context(), "SELECT instance_id,last_error,last_success FROM publisher_client_state").Scan(&id, &status, &success); e != nil {
		return e
	}
	queue := map[string]any{"state": "empty", "attempts": 0}
	var attempts int
	var next, created time.Time
	var key string
	var storedConsents []byte
	e = tx.QueryRow(r.Context(), "SELECT attempts,next_attempt,created_at,configuration_key,consents FROM publisher_client_outbox WHERE singleton").Scan(&attempts, &next, &created, &key, &storedConsents)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	if e == nil {
		state := "pending"
		if attempts > 0 {
			state = "retrying"
		}
		currentConsents, _ := json.Marshal(consents)
		if key != a.publisherConfigurationKey() || !bytes.Equal(compactJSON(storedConsents), compactJSON(currentConsents)) {
			state = "held"
		}
		queue = map[string]any{"state": state, "attempts": attempts, "next_attempt": next, "created_at": created}
	}
	reply(w, 200, map[string]any{"queue": queue, "instance_id": id, "configured": a.config.PublisherURL != "" && a.config.PublisherCredential != "", "auto_catalog": auto, "telemetry": batch, "last_error": status, "last_success": success})
	return nil
}
func (a *App) registerPublisherRoutes() {
	a.sessionOnly("GET /api/publisher/preview", permSettingsManage, a.publisherPreview)
}
