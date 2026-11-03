package app

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"
)

// Shared with admission accounting; ingestion holds the existing per-device lock.
// UTC day boundaries come from the evidence time, never the database timezone.
const discoveryNewDomainQuery = `NOT EXISTS(SELECT 1 FROM discovery_events old
 WHERE old.organization_id=$1 AND old.device_id=$2 AND old.scope=$3
 AND old.entity_id=q.entity_id AND old.kind='provider_domain_queried'
 AND old.evidence->>'provider'=q.provider
 AND old.occurred_at>=to_timestamp((q.evidence->>'observed_at')::bigint/86400*86400)
 AND old.occurred_at<to_timestamp((q.evidence->>'observed_at')::bigint/86400*86400+86400))`

func (a *App) storeDiscoveryReport(r *http.Request, tx pgx.Tx, org, device string, report *discoveryReport) error {
	if err := discoveryCapacity(r, tx, org, device, report); err != nil {
		return err
	}
	entities, _ := json.Marshal(report.Entities)
	if _, err := tx.Exec(r.Context(), `INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,display,sequence,last_seen,expires_at)
 SELECT $1,$2,$3,id,kind,coalesce(nullif(display,'null'::jsonb),'{}'::jsonb),$4,to_timestamp($5),to_timestamp($5)+interval '48 hours' FROM jsonb_to_recordset($6) AS x(id text,kind text,display jsonb)
 ON CONFLICT(organization_id,device_id,scope,id) DO UPDATE SET kind=excluded.kind,display=excluded.display,sequence=excluded.sequence,last_seen=excluded.last_seen,expires_at=excluded.expires_at`, org, device, report.Scope, report.Sequence, report.ObservedAt, entities); err != nil {
		return err
	}
	matches, _ := json.Marshal(report.Result.Identifications)
	// Stable observations refresh presence without manufacturing a new history row every heartbeat.
	if _, err := tx.Exec(r.Context(), `WITH input AS (SELECT * FROM jsonb_to_recordset($6) AS x(application_id text,entity_id text,signature_id text,signature_revision integer,state text,evidence jsonb)),
 changed AS (SELECT x.* FROM input x LEFT JOIN discovery_identifications i ON i.organization_id=$1 AND i.device_id=$2 AND i.scope=$3 AND i.entity_id=x.entity_id AND i.signature_id=x.signature_id WHERE i.entity_id IS NULL OR i.state<>x.state OR i.signature_revision<>x.signature_revision),
 events AS (INSERT INTO discovery_events(organization_id,device_id,scope,entity_id,kind,application_id,evidence,occurred_at) SELECT $1,$2,$3,entity_id,'identified',application_id,evidence,to_timestamp($5) FROM changed)
 INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence,last_seen,expires_at)
 SELECT $1,$2,$3,entity_id,application_id,signature_id,signature_revision,state,evidence,$4,to_timestamp($5),to_timestamp($5)+interval '48 hours' FROM input
 ON CONFLICT(organization_id,device_id,scope,entity_id,signature_id) DO UPDATE SET application_id=excluded.application_id,signature_revision=excluded.signature_revision,state=excluded.state,evidence=excluded.evidence,sequence=excluded.sequence,last_seen=excluded.last_seen,expires_at=excluded.expires_at`, org, device, report.Scope, report.Sequence, report.ObservedAt, matches); err != nil {
		return err
	}
	if len(report.Relations) > 0 {
		relations, _ := json.Marshal(report.Relations)
		if _, err := tx.Exec(r.Context(), `INSERT INTO discovery_relations(organization_id,device_id,scope,source_id,target_id,kind,source,sequence,expires_at)
	 SELECT $1,$2,$3,"from","to",kind,source,$4,to_timestamp($5)+interval '48 hours' FROM jsonb_to_recordset($6) AS x("from" text,"to" text,kind text,source text)
	 ON CONFLICT(organization_id,device_id,scope,source_id,target_id,kind) DO UPDATE SET sequence=excluded.sequence,source=excluded.source,expires_at=excluded.expires_at`, org, device, report.Scope, report.Sequence, report.ObservedAt, relations); err != nil {
			return err
		}
	}
	if len(report.Coverage) > 0 {
		coverage, _ := json.Marshal(report.Coverage)
		if _, err := tx.Exec(r.Context(), `INSERT INTO discovery_coverage(organization_id,device_id,scope,adapter,status,complete,checked_at,sequence,expires_at)
	 SELECT $1,$2,scope,adapter,status,complete,to_timestamp(checked_at),$3,to_timestamp($4)+interval '48 hours' FROM jsonb_to_recordset($5) AS x(scope text,adapter text,status text,complete boolean,checked_at bigint)
	 ON CONFLICT(organization_id,device_id,scope,adapter) DO UPDATE SET status=excluded.status,complete=excluded.complete,checked_at=excluded.checked_at,sequence=excluded.sequence,expires_at=excluded.expires_at`, org, device, report.Sequence, report.ObservedAt, coverage); err != nil {
			return err
		}
	}
	if len(report.Result.Communications) > 0 {
		communications, _ := json.Marshal(report.Result.Communications)
		if _, err := tx.Exec(r.Context(), `WITH input AS (SELECT * FROM jsonb_to_recordset($6) AS x(entity_id text,provider text,evidence jsonb)),
	 changed AS (SELECT x.* FROM input x LEFT JOIN discovery_communications c ON c.organization_id=$1 AND c.device_id=$2 AND c.scope=$3 AND c.entity_id=x.entity_id AND c.provider=x.provider WHERE c.entity_id IS NULL),
	 events AS (INSERT INTO discovery_events(organization_id,device_id,scope,entity_id,kind,evidence,occurred_at) SELECT $1,$2,$3,entity_id,'provider_contacted',jsonb_build_object('provider',provider,'evidence',evidence),to_timestamp($5) FROM changed)
	 INSERT INTO discovery_communications(organization_id,device_id,scope,entity_id,provider,sequence,last_seen,evidence,expires_at)
	 SELECT $1,$2,$3,entity_id,provider,$4,to_timestamp($5),evidence,to_timestamp($5)+interval '48 hours' FROM input
	 ON CONFLICT(organization_id,device_id,scope,entity_id,provider) DO UPDATE SET sequence=excluded.sequence,last_seen=excluded.last_seen,evidence=excluded.evidence,expires_at=excluded.expires_at`, org, device, report.Scope, report.Sequence, report.ObservedAt, communications); err != nil {
			return err
		}
	}
	if len(report.Result.Queries) > 0 {
		queries, _ := json.Marshal(report.Result.Queries)
		if _, err := tx.Exec(r.Context(), `INSERT INTO discovery_events(organization_id,device_id,scope,entity_id,kind,evidence,occurred_at,expires_at)
 SELECT $1,$2,$3,q.entity_id,'provider_domain_queried',jsonb_build_object('provider',q.provider,'evidence',q.evidence),to_timestamp((q.evidence->>'observed_at')::bigint),to_timestamp((q.evidence->>'observed_at')::bigint)+interval '48 hours'
 FROM jsonb_to_recordset($4) q(entity_id text,provider text,evidence jsonb) WHERE `+discoveryNewDomainQuery, org, device, report.Scope, queries); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(r.Context(), `DELETE FROM discovery_coverage WHERE organization_id=$1 AND device_id=$2 AND scope='server' AND adapter='ingest-capacity'`, org, device); err != nil {
		return err
	}
	return nil
}
