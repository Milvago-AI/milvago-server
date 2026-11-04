package app

// Analytics materializes only the columns its aggregates consume. Large event
// metadata, ciphertext and file lists belong to detail reads, not the flow CTE.
const cartographyProjection = `e.id,e.device_id,e.occurred_at,e.provider,e.tool,e.source,e.kind,e.model,e.action,e.sensitivity,e.conversation_id,e.correlation_id,e.collaborator_id`

// Count the fleet once, rather than evaluating one device scan for every group.
// Both sides keep their normal tenant policies and empty groups retain zero.
const deviceGroupsQuery = `WITH device_counts AS MATERIALIZED (
 SELECT group_id,count(*) AS devices FROM devices WHERE group_id IS NOT NULL GROUP BY group_id
) SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object(
 'id',g.id,'name',g.name,'description',g.description,'device_count',COALESCE(c.devices,0),
 'created_at',g.created_at,'updated_at',g.updated_at) ORDER BY g.name),'[]'::jsonb))
 FROM device_groups g LEFT JOIN device_counts c ON c.group_id=g.id`
