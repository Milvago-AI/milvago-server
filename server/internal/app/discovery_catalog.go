package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"go.yaml.in/yaml/v3"
)

// Inspect syntax nodes before constructing values: aliases cannot expand and
// quoted strings remain ordinary strings, even when they contain YAML markers.
func discoveryJSON(source string) (json.RawMessage, error) {
	if len(source) == 0 || len(source) > 96<<10 {
		return nil, bad("Discovery YAML exceeds its limit.")
	}
	if json.Valid([]byte(source)) {
		// Bound the representation actually embedded in signed policies: JSON's
		// HTML escaping and YAML scalar normalization can expand the input.
		raw, err := json.Marshal(json.RawMessage(source))
		if err != nil || len(raw) > 96<<10 {
			return nil, bad("Discovery catalog exceeds its serialized limit.")
		}
		return raw, nil
	}
	decoder := yaml.NewDecoder(strings.NewReader(source))
	var document, extra yaml.Node
	if decoder.Decode(&document) != nil || len(document.Content) != 1 || decoder.Decode(&extra) != io.EOF {
		return nil, bad("Use one valid discovery YAML document.")
	}
	count := 0
	var normalize func(*yaml.Node, int) (any, error)
	normalize = func(node *yaml.Node, depth int) (any, error) {
		count++
		if depth > 40 || count > 20000 {
			return nil, bad("Discovery YAML exceeds its complexity limit.")
		}
		if node.Anchor != "" || node.Alias != nil || node.Kind == yaml.AliasNode || node.Style&yaml.TaggedStyle != 0 {
			return nil, bad("YAML aliases, anchors and explicit tags are unsupported.")
		}
		switch node.Kind {
		case yaml.MappingNode:
			if node.Tag != "!!map" || len(node.Content)%2 != 0 {
				return nil, bad("Invalid discovery YAML mapping.")
			}
			value := map[string]any{}
			for index := 0; index < len(node.Content); index += 2 {
				key := node.Content[index]
				if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || len(key.Value) > 160 || key.Value == "<<" {
					return nil, bad("Discovery YAML keys must be unique strings; merge keys are unsupported.")
				}
				if _, exists := value[key.Value]; exists {
					return nil, bad("Duplicate discovery YAML key.")
				}
				if _, err := normalize(key, depth+1); err != nil {
					return nil, err
				}
				child, err := normalize(node.Content[index+1], depth+1)
				if err != nil {
					return nil, err
				}
				value[key.Value] = child
			}
			return value, nil
		case yaml.SequenceNode:
			if node.Tag != "!!seq" {
				return nil, bad("Unsupported discovery YAML tag.")
			}
			value := make([]any, 0, len(node.Content))
			for _, item := range node.Content {
				child, err := normalize(item, depth+1)
				if err != nil {
					return nil, err
				}
				value = append(value, child)
			}
			return value, nil
		case yaml.ScalarNode:
			switch node.Tag {
			case "!!str":
				return node.Value, nil
			case "!!null":
				return nil, nil
			case "!!int", "!!float", "!!bool":
				var value any
				if err := node.Decode(&value); err != nil {
					return nil, bad("Invalid discovery YAML scalar.")
				}
				return value, nil
			}
		}
		return nil, bad("Unsupported discovery YAML value.")
	}
	value, err := normalize(document.Content[0], 0)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, bad("Invalid discovery YAML.")
	}
	if len(raw) > 96<<10 {
		return nil, bad("Discovery catalog exceeds its serialized limit.")
	}
	return raw, nil
}

func currentDiscoveryCatalog(ctx context.Context, tx pgx.Tx, org string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := tx.QueryRow(ctx, `SELECT content FROM discovery_catalogs WHERE organization_id=$1 FOR SHARE`, org).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return discoveryFactory, nil
	}
	return raw, err
}
func (a *App) discoveryCatalogMetadata(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	raw, err := currentDiscoveryCatalog(r.Context(), tx, s.OrganizationID)
	if err != nil {
		return err
	}
	var catalog struct {
		Version    int   `json:"version"`
		Revision   int64 `json:"revision"`
		Signatures []struct {
			ID            string `json:"id"`
			ApplicationID string `json:"application_id"`
			Name          string `json:"name"`
			Revision      int    `json:"revision"`
			Provenance    string `json:"provenance"`
		} `json:"signatures"`
	}
	if json.Unmarshal(raw, &catalog) != nil {
		return errors.New("invalid stored discovery catalog")
	}
	reply(w, 200, catalog)
	return nil
}
func (a *App) discoveryCatalogDraft(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var draft string
	var revision int64
	err := tx.QueryRow(r.Context(), `SELECT draft,draft_revision FROM discovery_catalogs WHERE organization_id=$1`, s.OrganizationID).Scan(&draft, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		draft = string(discoveryFactory)
		revision = 0
	} else if err != nil {
		return err
	}
	published, err := currentDiscoveryCatalog(r.Context(), tx, s.OrganizationID)
	if err != nil {
		return err
	}
	reply(w, 200, map[string]any{"source": draft, "revision": revision, "published": published})
	return nil
}
func (a *App) putDiscoveryCatalogDraft(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var body struct {
		Source   string `json:"source"`
		Revision int64  `json:"revision"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	raw, err := discoveryJSON(body.Source)
	if err != nil {
		return err
	}
	if err = discoveryEngine(r.Context(), map[string]any{"op": "compile", "catalog": raw}, nil); err != nil {
		return err
	}
	var affected int64
	if body.Revision == 0 {
		tag, e := tx.Exec(r.Context(), `INSERT INTO discovery_catalogs(organization_id,draft,content) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, s.OrganizationID, body.Source, discoveryFactory)
		if e != nil {
			return e
		}
		affected = tag.RowsAffected()
	} else {
		tag, e := tx.Exec(r.Context(), `UPDATE discovery_catalogs SET draft=$2,draft_revision=nextval('shadow_revision'),updated_at=now() WHERE organization_id=$1 AND draft_revision=$3`, s.OrganizationID, body.Source, body.Revision)
		if e != nil {
			return e
		}
		affected = tag.RowsAffected()
	}
	if affected != 1 {
		return apiError{409, "revision_conflict", "Refresh the discovery draft before saving."}
	}
	if err = audit(r.Context(), tx, s.OrganizationID, s.UserID, "discovery.catalog.draft", "discovery"); err != nil {
		return err
	}
	var next int64
	if err = tx.QueryRow(r.Context(), `SELECT draft_revision FROM discovery_catalogs WHERE organization_id=$1`, s.OrganizationID).Scan(&next); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	reply(w, 200, map[string]any{"source": body.Source, "revision": next})
	return nil
}
func (a *App) compileDiscoveryCatalog(w http.ResponseWriter, r *http.Request, _ pgx.Tx, _ *Session) error {
	var body struct {
		Source string `json:"source"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	raw, err := discoveryJSON(body.Source)
	if err != nil {
		return err
	}
	var result json.RawMessage
	if err = discoveryEngine(r.Context(), map[string]any{"op": "compile", "catalog": raw}, &result); err != nil {
		return err
	}
	reply(w, 200, result)
	return nil
}
func (a *App) evaluateDiscoveryCatalog(w http.ResponseWriter, r *http.Request, _ pgx.Tx, _ *Session) error {
	var body struct {
		Source   string          `json:"source"`
		Snapshot json.RawMessage `json:"snapshot"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	raw, err := discoveryJSON(body.Source)
	if err != nil {
		return err
	}
	var result json.RawMessage
	if err = discoveryEngine(r.Context(), map[string]any{"op": "evaluate", "catalog": raw, "snapshot": body.Snapshot}, &result); err != nil {
		return err
	}
	reply(w, 200, result)
	return nil
}
func (a *App) publishDiscoveryCatalog(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var body struct {
		Revision int64  `json:"revision"`
		Reason   string `json:"reason"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	if err := a.requireFreshMFA(r, tx, s); err != nil {
		return err
	}
	if len(strings.TrimSpace(body.Reason)) < 8 || len(body.Reason) > 1000 {
		return bad(msgReasonLengthRequired)
	}
	var source string
	var revision int64
	var current json.RawMessage
	if err := tx.QueryRow(r.Context(), `SELECT draft,draft_revision,content FROM discovery_catalogs WHERE organization_id=$1 FOR UPDATE`, s.OrganizationID).Scan(&source, &revision, &current); err != nil {
		return err
	}
	if revision != body.Revision {
		return apiError{409, "revision_conflict", "Refresh the discovery draft before publishing."}
	}
	raw, err := discoveryJSON(source)
	if err != nil {
		return err
	}
	if err = discoveryEngine(r.Context(), map[string]any{"op": "compile", "catalog": raw}, nil); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return bad("Invalid discovery catalog.")
	}
	var published struct {
		Revision int64 `json:"revision"`
	}
	if json.Unmarshal(current, &published) != nil || published.Revision <= 0 || published.Revision == 1<<63-1 {
		return errors.New("invalid published discovery catalog revision")
	}
	var next int64
	// A bundled baseline can be ahead of the database sequence on a new server.
	// The locked organization's published content must still advance strictly.
	if err = tx.QueryRow(r.Context(), `SELECT GREATEST(nextval('shadow_revision'), $1::bigint + 1)`, published.Revision).Scan(&next); err != nil {
		return err
	}
	object["revision"], _ = json.Marshal(next)
	raw, _ = json.Marshal(object)
	if _, err = tx.Exec(r.Context(), `UPDATE discovery_catalogs SET content=$2,revision=$3,updated_at=now() WHERE organization_id=$1`, s.OrganizationID, raw, next); err != nil {
		return err
	}
	if err = privacyAudit(r, tx, s, "discovery.catalog.publish", "discovery", map[string]any{"reason": strings.TrimSpace(body.Reason), "revision": next}); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	reply(w, 200, map[string]any{"revision": next})
	return nil
}

func decodeDiscoveryRaw(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil {
		return bad("Invalid discovery report.")
	}
	return nil
}
