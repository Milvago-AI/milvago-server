package app

import "strings"

func conversationHeaderFilter(f shadowFilter) bool {
	for key := range f.Criteria {
		switch key {
		case "from", "to", "view", "device_id", "device_name", "provider", "tool", "kind", "regex":
		default:
			return false
		}
	}
	return true
}

// The snapshot timestamp completes the ordering index's prefix as well as the
// logical primary key. Stale statistics must not turn a page event lookup into
// a walk through every retained timestamp on the device.
func conversationPageEventLookup(alias, id, at string) string {
	return " JOIN LATERAL (SELECT e.* FROM shadow_events e WHERE e.organization_id=" + alias + ".organization_id AND e.device_id=" + alias + ".device_id AND e.id=" + alias + "." + id + " AND e.occurred_at=" + alias + "." + at + " OFFSET 0) e ON true"
}

// Legacy lists filter individual records before computing their counters. A
// known conversation ID therefore needs no retained-history expansion. Resolve
// only missing IDs through correlation; chronological recovery is restricted to
// the ambiguous scopes that actually occur in the selected candidate records.
func legacyConversationPageKeys(f shadowFilter) string {
	join := " FROM public.milvago_conversation_candidates($1,$2) e"
	if !conversationHeaderFilter(f) {
		join = strings.Replace(shadowJoins, "FROM shadow_events e", "FROM public.milvago_conversation_candidates($1,$2) h"+conversationPageEventLookup("h", "id", "occurred_at"), 1)
	}
	fallback := strings.TrimPrefix(conversationKeysFrom("TRUE", "fallback_events", "fallback_conversation_keys"), "WITH ")
	return `WITH candidate_events AS MATERIALIZED (
 SELECT e.organization_id,e.id,e.device_id,e.occurred_at,e.kind,e.source,e.tool,e.provider,e.conversation_id,e.correlation_id,e.characters
 ` + join + ` WHERE ` + f.Where + ` AND NOT ` + attachmentOnly("e") + `),
 page_correlation_requests AS MATERIALIZED (
 SELECT DISTINCT organization_id,device_id,source,tool,provider,correlation_id FROM candidate_events
 WHERE conversation_id='' AND correlation_id<>''),
 page_correlation_batches AS MATERIALIZED (
 SELECT organization_id,device_id,source,tool,provider,array_agg(correlation_id ORDER BY correlation_id) AS keys
 FROM (SELECT r.*,(row_number() OVER(PARTITION BY organization_id,device_id,source,tool,provider ORDER BY correlation_id)-1)/256 AS batch
 FROM page_correlation_requests r) r GROUP BY organization_id,device_id,source,tool,provider,batch),
 page_correlations AS MATERIALIZED (
 SELECT r.organization_id,r.device_id,r.source,r.tool,r.provider,k.* FROM page_correlation_batches r
 JOIN LATERAL public.milvago_conversation_correlation_keys(r.organization_id,r.device_id,r.source,r.tool,r.provider,r.keys) k ON true),
 page_identified AS MATERIALIZED (
 SELECT e.*,CASE WHEN e.conversation_id<>'' THEN 'conv:'||e.conversation_id
 WHEN k.conversation_id IS NOT NULL THEN 'conv:'||k.conversation_id
 WHEN e.correlation_id<>'' THEN 'corr:'||e.correlation_id ELSE 'event:'||e.id::text END AS initial_key
 FROM candidate_events e LEFT JOIN page_correlations k ON k.organization_id=e.organization_id AND k.device_id=e.device_id
 AND k.source=e.source AND k.tool=e.tool AND k.provider=e.provider AND k.correlation_id=e.correlation_id),
 fallback_scopes AS MATERIALIZED (
 SELECT DISTINCT organization_id,device_id,source,tool,provider FROM page_identified
 WHERE source='browser' AND provider IN ('chatgpt.com','chat.openai.com') AND initial_key NOT LIKE 'conv:%'),
 fallback_events AS MATERIALIZED (
 SELECT e.*,NULL::tid AS ctid,NULL::oid AS tableoid FROM fallback_scopes p
 JOIN LATERAL public.milvago_conversation_scope_headers(p.organization_id,p.device_id,p.source,p.tool,p.provider) e ON true),
 ` + fallback + `,
 conversation_keys AS (
 SELECT e.*,coalesce(k.group_key,e.initial_key) AS group_key FROM page_identified e
 LEFT JOIN fallback_conversation_keys k ON k.device_id=e.device_id AND k.id=e.id) `
}
