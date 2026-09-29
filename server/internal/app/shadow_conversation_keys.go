package app

// Resolve keys before applying display filters so the list and detail agree even
// when the opening exchange falls outside the selected period. RLS bounds every
// input to the current organization. Scope is a server-owned SQL expression.
func conversationKeys(scope string) string {
	return `WITH conversation_events AS (
  SELECT id,device_id,provider,source,tool,occurred_at,kind,conversation_id,correlation_id
  FROM shadow_events WHERE ` + scope + `),
 correlation_links AS (
  SELECT device_id,provider,source,tool,correlation_id,min(conversation_id) AS conversation_id
  FROM conversation_events WHERE conversation_id<>'' AND correlation_id<>''
  GROUP BY device_id,provider,source,tool,correlation_id),
 identified AS (
  SELECT e.*,CASE WHEN e.conversation_id<>'' THEN 'conv:'||e.conversation_id
   WHEN l.conversation_id IS NOT NULL THEN 'conv:'||l.conversation_id
   WHEN e.correlation_id<>'' THEN 'corr:'||e.correlation_id
   ELSE 'event:'||e.id::text END AS initial_key
  FROM conversation_events e LEFT JOIN correlation_links l
  ON (l.device_id,l.provider,l.source,l.tool,l.correlation_id)=(e.device_id,e.provider,e.source,e.tool,e.correlation_id)),
 chatgpt_threads AS (
  SELECT device_id,provider,source,tool,initial_key,min(occurred_at) AS started_at
  FROM identified WHERE source='browser' AND provider IN ('chatgpt.com','chat.openai.com')
  GROUP BY device_id,provider,source,tool,initial_key
  HAVING bool_or(kind IN ('prompt','response'))),
 ordered_threads AS (
  SELECT *,lead(initial_key) OVER chronology AS next_key
  FROM chatgpt_threads
  WINDOW chronology AS (PARTITION BY device_id,provider,source,tool ORDER BY started_at,initial_key)),
 conversation_keys AS (
  SELECT e.id,e.device_id,
   CASE WHEN o.initial_key NOT LIKE 'conv:%' AND o.next_key LIKE 'conv:%'
   THEN o.next_key ELSE e.initial_key END AS group_key
  FROM identified e LEFT JOIN ordered_threads o
  ON (o.device_id,o.provider,o.source,o.tool,o.initial_key)=(e.device_id,e.provider,e.source,e.tool,e.initial_key)) `
}
