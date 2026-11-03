CREATE INDEX IF NOT EXISTS shadow_events_recent_conversation_headers
 ON public.shadow_events(organization_id,source,occurred_at DESC,id DESC,device_id DESC)
 INCLUDE(tool,provider,kind,conversation_id,correlation_id,characters,collaborator_id)
 WHERE source IN ('browser','native') AND NOT(kind='navigation' AND conversation_id='' AND correlation_id='');
CREATE INDEX IF NOT EXISTS shadow_events_retained_correlation_headers
 ON public.shadow_events(organization_id,device_id,source,tool,provider,correlation_id)
 INCLUDE(id,kind,conversation_id,occurred_at,characters) WHERE correlation_id<>'';
CREATE INDEX IF NOT EXISTS shadow_events_conversation_scope_headers
 ON public.shadow_events(organization_id,device_id,source,tool,provider,occurred_at,id)
 INCLUDE(kind,conversation_id,correlation_id,characters,collaborator_id)
 WHERE NOT(kind='navigation' AND conversation_id='' AND correlation_id='');

CREATE OR REPLACE FUNCTION public.milvago_conversation_candidates(requested_from timestamptz,requested_to timestamptz)
 RETURNS TABLE(organization_id uuid,id uuid,device_id uuid,occurred_at timestamptz,kind text,source text,tool text,provider text,
 conversation_id text,correlation_id text,characters integer,collaborator_id uuid)
 LANGUAGE plpgsql STABLE STRICT SECURITY INVOKER SET search_path=pg_catalog,public SET enable_sort=off AS $function$
DECLARE tenant uuid:=nullif(current_setting('milvago.organization_id',true),'')::uuid;
BEGIN
 IF tenant IS NULL THEN RETURN; END IF;
 RETURN QUERY EXECUTE $query$
 SELECT e.organization_id,e.id,e.device_id,e.occurred_at,e.kind,e.source,e.tool,e.provider,e.conversation_id,e.correlation_id,e.characters,e.collaborator_id
 FROM public.shadow_events e WHERE e.organization_id=$1 AND e.occurred_at>=$2 AND e.occurred_at<=$3
 AND e.source IN ('browser','native') AND NOT(e.kind='navigation' AND e.conversation_id='' AND e.correlation_id='')
 ORDER BY e.source,e.occurred_at DESC,e.id DESC,e.device_id DESC
 $query$ USING tenant,requested_from,requested_to;
END $function$;

CREATE OR REPLACE FUNCTION public.milvago_conversation_correlation_keys(requested_organization uuid,requested_device uuid,
 requested_source text,requested_tool text,requested_provider text,key_values text[])
 RETURNS TABLE(correlation_id text,conversation_id text)
 LANGUAGE plpgsql STABLE STRICT SECURITY INVOKER SET search_path=pg_catalog,public SET enable_sort=off AS $function$
BEGIN
 IF cardinality(key_values)>256 THEN
  RAISE EXCEPTION 'Correlation key batch exceeds its bound' USING ERRCODE='22023';
 END IF;
 RETURN QUERY EXECUTE $query$
 SELECT e.correlation_id,min(e.conversation_id) FROM public.shadow_events e
 WHERE e.organization_id=$1 AND e.device_id=$2 AND e.source=$3 AND e.tool=$4 AND e.provider=$5
 AND e.correlation_id<>'' AND e.correlation_id=ANY($6) AND e.conversation_id<>'' GROUP BY e.correlation_id ORDER BY e.correlation_id
 $query$ USING requested_organization,requested_device,requested_source,requested_tool,requested_provider,key_values;
END $function$;

CREATE OR REPLACE FUNCTION public.milvago_conversation_scope_headers(requested_organization uuid,requested_device uuid,
 requested_source text,requested_tool text,requested_provider text)
 RETURNS TABLE(organization_id uuid,id uuid,device_id uuid,occurred_at timestamptz,kind text,source text,tool text,provider text,
 conversation_id text,correlation_id text,characters integer,collaborator_id uuid)
 LANGUAGE plpgsql STABLE STRICT SECURITY INVOKER SET search_path=pg_catalog,public SET enable_sort=off AS $function$
BEGIN
 RETURN QUERY EXECUTE $query$
 SELECT e.organization_id,e.id,e.device_id,e.occurred_at,e.kind,e.source,e.tool,e.provider,e.conversation_id,e.correlation_id,e.characters,e.collaborator_id
 FROM public.shadow_events e WHERE e.organization_id=$1 AND e.device_id=$2 AND e.source=$3 AND e.tool=$4 AND e.provider=$5
 AND NOT(e.kind='navigation' AND e.conversation_id='' AND e.correlation_id='') ORDER BY e.occurred_at,e.id
 $query$ USING requested_organization,requested_device,requested_source,requested_tool,requested_provider;
END $function$;

REVOKE ALL ON FUNCTION public.milvago_conversation_candidates(timestamptz,timestamptz),
 public.milvago_conversation_correlation_keys(uuid,uuid,text,text,text,text[]),
 public.milvago_conversation_scope_headers(uuid,uuid,text,text,text) FROM PUBLIC;
