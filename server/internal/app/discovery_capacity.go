package app

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"
)

func discoveryCapacity(r *http.Request, tx pgx.Tx, org, device string, report *discoveryReport) error {
	// The fresh device row lock serializes all reports for this device. Limits
	// count new keys, not retries or refreshes of an existing observation.
	var expired pgx.Batch
	for _, table := range []string{"discovery_entities", "discovery_identifications", "discovery_communications", "discovery_relations", "discovery_coverage", "discovery_events"} {
		expired.Queue(`DELETE FROM `+table+` WHERE organization_id=$1 AND device_id=$2 AND expires_at<=now()`, org, device)
	}
	// Pipeline the ordered deletes before admission. Cascades and statement
	// snapshots keep their existing order; a failure still aborts this transaction.
	if err := tx.SendBatch(r.Context(), &expired).Close(); err != nil {
		return err
	}
	raw, _ := json.Marshal(report)
	var identityConflict, capacity bool
	err := tx.QueryRow(r.Context(), `WITH
 e AS (SELECT * FROM jsonb_to_recordset($4::jsonb->'entities') x(id text,kind text)),
 i AS (SELECT * FROM jsonb_to_recordset($4::jsonb->'result'->'identifications') x(entity_id text,signature_id text,state text,signature_revision integer)),
 c AS (SELECT * FROM jsonb_to_recordset($4::jsonb->'result'->'communications') x(entity_id text,provider text)),
 q AS (SELECT * FROM jsonb_to_recordset(coalesce($4::jsonb->'result'->'queries','[]'::jsonb)) x(entity_id text,provider text,evidence jsonb)),
 nq AS (SELECT q.* FROM q WHERE `+discoveryNewDomainQuery+`),
 r AS (SELECT * FROM jsonb_to_recordset($4::jsonb->'relations') x("from" text,"to" text,kind text)),
 v AS (SELECT DISTINCT scope,adapter FROM jsonb_to_recordset($4::jsonb->'coverage') x(scope text,adapter text)),
 ni AS (SELECT i.* FROM i WHERE NOT EXISTS(SELECT 1 FROM discovery_identifications old WHERE old.organization_id=$1 AND old.device_id=$2 AND old.scope=$3 AND old.entity_id=i.entity_id AND old.signature_id=i.signature_id)),
 nc AS (SELECT c.* FROM c WHERE NOT EXISTS(SELECT 1 FROM discovery_communications old WHERE old.organization_id=$1 AND old.device_id=$2 AND old.scope=$3 AND old.entity_id=c.entity_id AND old.provider=c.provider)),
 changed AS (SELECT i.* FROM i WHERE NOT EXISTS(SELECT 1 FROM discovery_identifications old WHERE old.organization_id=$1 AND old.device_id=$2 AND old.scope=$3 AND old.entity_id=i.entity_id AND old.signature_id=i.signature_id AND old.state=i.state AND old.signature_revision=i.signature_revision))
 SELECT EXISTS(SELECT 1 FROM e JOIN discovery_entities old ON old.organization_id=$1 AND old.device_id=$2 AND old.scope=$3 AND old.id=e.id WHERE old.kind<>e.kind),
 (SELECT count(*) FROM discovery_entities WHERE organization_id=$1 AND device_id=$2)+(SELECT count(*) FROM e WHERE NOT EXISTS(SELECT 1 FROM discovery_entities old WHERE old.organization_id=$1 AND old.device_id=$2 AND old.scope=$3 AND old.id=e.id))>24000
 OR (SELECT count(*) FROM discovery_identifications WHERE organization_id=$1 AND device_id=$2)+(SELECT count(*) FROM ni)>48000
 OR (SELECT count(*) FROM discovery_communications WHERE organization_id=$1 AND device_id=$2)+(SELECT count(*) FROM nc)>16000
 OR (SELECT count(*) FROM discovery_relations WHERE organization_id=$1 AND device_id=$2)+(SELECT count(*) FROM r WHERE NOT EXISTS(SELECT 1 FROM discovery_relations old WHERE old.organization_id=$1 AND old.device_id=$2 AND old.scope=$3 AND old.source_id=r."from" AND old.target_id=r."to" AND old.kind=r.kind))>48000
 OR (SELECT count(*) FROM discovery_coverage WHERE organization_id=$1 AND device_id=$2 AND NOT(scope='server' AND adapter='ingest-capacity'))+(SELECT count(*) FROM v WHERE NOT EXISTS(SELECT 1 FROM discovery_coverage old WHERE old.organization_id=$1 AND old.device_id=$2 AND old.scope=v.scope AND old.adapter=v.adapter))>2048
 OR (SELECT count(*) FROM discovery_events WHERE organization_id=$1 AND device_id=$2)+(SELECT count(*) FROM changed)+(SELECT count(*) FROM nc)+(SELECT count(*) FROM nq)>50000`, org, device, report.Scope, raw).Scan(&identityConflict, &capacity)
	if err != nil {
		return err
	}
	if identityConflict {
		return apiError{409, "discovery_identity_conflict", "Discovery entity kind cannot change within an identity."}
	}
	if capacity {
		return apiError{409, "discovery_capacity", "Discovery storage capacity reached for this device."}
	}
	return nil
}

func rejectDiscoveryCapacity(r *http.Request, tx pgx.Tx, org, device string, sequence int64) error {
	// A rejected page must never advance the scan ledger or be acknowledged.
	// Commit only a fixed server-owned visibility marker after rolling it back.
	if _, err := tx.Exec(r.Context(), `ROLLBACK TO SAVEPOINT discovery_page`); err != nil {
		return err
	}
	if _, err := tx.Exec(r.Context(), `INSERT INTO discovery_coverage(organization_id,device_id,scope,adapter,status,complete,checked_at,sequence,expires_at) VALUES($1,$2,'server','ingest-capacity','saturated',false,now(),$3,now()+interval '48 hours') ON CONFLICT(organization_id,device_id,scope,adapter) DO UPDATE SET status='saturated',complete=false,checked_at=now(),sequence=excluded.sequence,expires_at=excluded.expires_at`, org, device, sequence); err != nil {
		return err
	}
	if err := tx.Commit(r.Context()); err != nil {
		return err
	}
	return apiError{409, "discovery_capacity", "Discovery storage capacity reached for this device."}
}
