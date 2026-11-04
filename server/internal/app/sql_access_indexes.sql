-- Typed routing times avoid parsing every historical JSON payload on a read.
-- The trigger also covers imports and preserves the payload as the source of truth.
ALTER TABLE public.detector_health ADD COLUMN IF NOT EXISTS window_start timestamptz;
ALTER TABLE public.detector_health ADD COLUMN IF NOT EXISTS window_end timestamptz;
CREATE OR REPLACE FUNCTION public.detector_health_window_times() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $function$
BEGIN
 NEW.window_start:=(NEW.payload->>'window_start')::timestamptz;
 NEW.window_end:=(NEW.payload->>'window_end')::timestamptz;
 RETURN NEW;
END $function$;
REVOKE ALL ON FUNCTION public.detector_health_window_times() FROM PUBLIC;
CREATE OR REPLACE TRIGGER detector_health_window_times BEFORE INSERT OR UPDATE ON public.detector_health
 FOR EACH ROW EXECUTE FUNCTION public.detector_health_window_times();
DO $migration$
DECLARE tenant uuid; previous_tenant text:=current_setting('milvago.organization_id',true);
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.schema_migrations WHERE version=2026110202) THEN
  FOR tenant IN SELECT id FROM public.organizations LOOP
   PERFORM set_config('milvago.organization_id',tenant::text,true);
   UPDATE public.detector_health SET window_start=(payload->>'window_start')::timestamptz,window_end=(payload->>'window_end')::timestamptz;
  END LOOP;
  PERFORM set_config('milvago.organization_id',coalesce(previous_tenant,''),true);
  INSERT INTO public.schema_migrations(version) VALUES(2026110202);
 END IF;
END $migration$;
CREATE INDEX IF NOT EXISTS detector_health_window_lookup ON public.detector_health(organization_id,window_end,device_id);

-- These prefixes serve the existing reverse lookups and foreign-key checks.
-- Keep high-volume event indexes partial where the key is usually absent.
CREATE INDEX IF NOT EXISTS organizations_parent_lookup ON public.organizations(parent_id,id);
CREATE INDEX IF NOT EXISTS memberships_user_lookup ON public.memberships(user_id,organization_id) INCLUDE(role);
CREATE INDEX IF NOT EXISTS sessions_user_lookup ON public.sessions(user_id);
CREATE INDEX IF NOT EXISTS dlp_decisions_policy_lookup ON public.dlp_decisions(organization_id,policy_fingerprint);
CREATE INDEX IF NOT EXISTS dlp_history_policy_lookup ON public.dlp_device_policy_history(organization_id,fingerprint);
CREATE INDEX IF NOT EXISTS shadow_events_collaborator_lookup ON public.shadow_events(organization_id,collaborator_id) WHERE collaborator_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS device_collaborators_subject_lookup ON public.device_collaborators(organization_id,collaborator_id);
CREATE INDEX IF NOT EXISTS identity_reveals_session_lookup ON public.identity_reveals(session_hash,organization_id,collaborator_id,privacy_revision,expires_at);
CREATE INDEX IF NOT EXISTS identity_reveals_subject_lookup ON public.identity_reveals(organization_id,collaborator_id);
CREATE INDEX IF NOT EXISTS detector_health_received_lookup ON public.detector_health(organization_id,received_at,device_id);

-- Covering event indexes still visit the heap until VACUUM marks pages visible.
-- The default 20% trigger leaves an active multi-million-row table's recent
-- pages dirty for too long. Apply read-oriented defaults only when neither an
-- explicit table choice nor a stricter global setting already governs them.
DO $visibility$
DECLARE option_name text; desired text; existing text[];
BEGIN
 SELECT reloptions INTO existing FROM pg_class WHERE oid='public.shadow_events'::regclass;
 FOR option_name,desired IN SELECT * FROM (VALUES
  ('autovacuum_vacuum_insert_scale_factor','0.001'),
  ('autovacuum_vacuum_scale_factor','0.005'),
  ('autovacuum_analyze_scale_factor','0.005')) defaults(name,value) LOOP
  IF NOT EXISTS(SELECT 1 FROM unnest(coalesce(existing,ARRAY[]::text[])) o WHERE split_part(o,'=',1)=option_name)
   AND current_setting(option_name)::numeric>desired::numeric THEN
   EXECUTE format('ALTER TABLE public.shadow_events SET (%I=%L)',option_name,desired);
  END IF;
 END LOOP;
END $visibility$;
