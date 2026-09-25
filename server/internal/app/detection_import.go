package app

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// importDetectionCatalog accepts signed bytes, never a download location. The
// same verifier and publisher revision floor protect automatic and manual import.
func (a *App) importDetectionCatalog(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	// Manual import is the console half of this route pair; see publishDetectionCatalog
	// for why the flag is checked first and refuses exactly like a non-owner.
	if !a.config.ConsoleDebug {
		return forbidden()
	}
	if !isInstanceOwner(r.Context(), tx, s) {
		return forbidden()
	}
	var body struct {
		ExpectedRevision int64             `json:"expected_revision"`
		Envelope         publisherEnvelope `json:"envelope"`
		Publish          bool              `json:"publish"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1536*1024))
	d.DisallowUnknownFields()
	if d.Decode(&body) != nil || d.Decode(new(any)) != io.EOF {
		return bad("Invalid signed catalogue import.")
	}
	if err := a.requireFreshMFA(r, tx, s); err != nil {
		return err
	}
	// Match publisherPass's lock order: publisher state, then catalogue.
	var publisherRevision int64
	var publisherHash string
	if err := tx.QueryRow(r.Context(), "SELECT publisher_revision,publisher_hash FROM publisher_client_state WHERE singleton FOR UPDATE").Scan(&publisherRevision, &publisherHash); err != nil {
		return err
	}
	if _, err := tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock(726403212)"); err != nil {
		return err
	}
	revision, _, err := currentDetectionRaw(r.Context(), tx)
	if err != nil {
		return err
	}
	if revision != body.ExpectedRevision {
		return apiError{409, "revision_conflict", "Catalogue changed. Reload before importing."}
	}
	raw, err := json.Marshal(body.Envelope)
	if err != nil {
		return err
	}
	header, content, err := decodePublisherEnvelope(raw, ed25519.PublicKey(a.config.PublisherPublicKey), publisherRevision, publisherHash, time.Now().UTC())
	if err != nil {
		return bad("Signed catalogue is invalid, expired or incompatible.")
	}
	decoded, err := decodeDetection(content)
	if err != nil {
		return err
	}
	if body.Publish {
		// A replay cannot replace a locally edited catalogue or create a new revision.
		if header.Revision <= publisherRevision {
			return apiError{409, "catalog_already_imported", "This publisher revision has already been imported."}
		}
		if err = tx.QueryRow(r.Context(), "INSERT INTO detection_catalogs(content,content_hash,source,publisher_signature) VALUES($1,$2,'imported',$3) RETURNING revision", content, header.ContentHash, body.Envelope.Signature).Scan(&revision); err != nil {
			return err
		}
		if _, err = tx.Exec(r.Context(), "UPDATE publisher_client_state SET publisher_revision=$1,publisher_hash=$2 WHERE singleton", header.Revision, header.ContentHash); err != nil {
			return err
		}
		if err = privacyAudit(r, tx, s, "detection.catalog.import", "instance", map[string]any{"revision": revision, "publisher_revision": header.Revision, "content_hash": header.ContentHash}); err != nil {
			return err
		}
		if err = tx.Commit(r.Context()); err != nil {
			return err
		}
	}
	reply(w, 200, map[string]any{"revision": revision, "content": decoded, "can_publish": true, "published": body.Publish, "publisher_revision": header.Revision, "content_hash": header.ContentHash})
	return nil
}
