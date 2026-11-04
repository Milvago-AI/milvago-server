package app

import (
	"net/http"

	"github.com/jackc/pgx/v5"
)

// A failed VM source must not keep a proven-stopped host process forever.
// Conversely, lack of access must never retire an observation from that source.
// Only the closed, built-in process-source contracts can currently prove absence;
// HTTP, installation, provider traffic and unknown adapters keep their expiry.
func reconcileDiscoveryProcessSources(r *http.Request, tx pgx.Tx, org, device string, report *discoveryReport) error {
	var host, guest, evaluationFailed bool
	if err := tx.QueryRow(r.Context(), `SELECT
 EXISTS(SELECT 1 FROM discovery_coverage c JOIN devices d ON d.organization_id=c.organization_id AND d.id=c.device_id
 WHERE c.organization_id=$1 AND c.device_id=$2 AND c.scope=$3 AND c.adapter='host' AND c.sequence=$4 AND c.complete AND c.status='available'
 AND (lower(d.platform)='linux' OR (lower(d.platform)='windows' AND EXISTS(SELECT 1 FROM discovery_coverage interpreter
 WHERE interpreter.organization_id=$1 AND interpreter.device_id=$2 AND interpreter.scope=$3 AND interpreter.adapter='windows-interpreter-entries'
 AND interpreter.sequence=$4 AND interpreter.complete AND interpreter.status='available')))),
 EXISTS(SELECT 1 FROM discovery_coverage c WHERE c.organization_id=$1 AND c.device_id=$2 AND c.sequence=$4
 AND c.adapter IN ('hyper-v-guest','libvirt-guest','virtualbox-guest','vmware-guest') AND c.complete AND c.status='available'),
 EXISTS(SELECT 1 FROM discovery_coverage c WHERE c.organization_id=$1 AND c.device_id=$2 AND c.scope=$3 AND c.sequence=$4
 AND c.adapter IN ('detection-engine','report-delivery') AND (NOT c.complete OR c.status<>'available'))`, org, device, report.Scope, report.Sequence).Scan(&host, &guest, &evaluationFailed); err != nil {
		return err
	}
	// Coverage can arrive on an earlier page; consult the persisted whole scan.
	// Successful collection alone cannot prove absence after evaluation failed.
	if evaluationFailed {
		return nil
	}
	if host {
		if _, err := tx.Exec(r.Context(), `DELETE FROM discovery_identifications i WHERE i.organization_id=$1 AND i.device_id=$2 AND i.scope=$3 AND i.sequence<$4
 AND jsonb_typeof(i.evidence)='array' AND jsonb_array_length(i.evidence)>0
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(i.evidence) e WHERE e->>'source' IS DISTINCT FROM 'host_process')`, org, device, report.Scope, report.Sequence); err != nil {
			return err
		}
	}
	if guest {
		if _, err := tx.Exec(r.Context(), `DELETE FROM discovery_identifications i WHERE i.organization_id=$1 AND i.device_id=$2 AND i.scope=$3 AND i.sequence<$4
 AND jsonb_typeof(i.evidence)='array' AND jsonb_array_length(i.evidence)>0
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(i.evidence) e WHERE e->>'source' IS DISTINCT FROM 'guest_process')
 AND EXISTS(SELECT 1 FROM discovery_relations relation JOIN discovery_entities parent
 ON parent.organization_id=relation.organization_id AND parent.device_id=relation.device_id AND parent.scope=relation.scope AND parent.id=relation.source_id
 JOIN discovery_coverage c
 ON c.organization_id=relation.organization_id AND c.device_id=relation.device_id AND c.scope=relation.source_id
 WHERE relation.organization_id=$1 AND relation.device_id=$2 AND relation.scope=$3 AND relation.target_id=i.entity_id AND relation.kind='contains'
 AND parent.kind='vm' AND parent.sequence=$4
 AND c.sequence=$4 AND c.adapter IN ('hyper-v-guest','libvirt-guest','virtualbox-guest','vmware-guest') AND c.complete AND c.status='available')`, org, device, report.Scope, report.Sequence); err != nil {
			return err
		}
	}
	return nil
}
