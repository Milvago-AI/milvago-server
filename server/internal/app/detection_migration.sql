CREATE TABLE IF NOT EXISTS detection_catalogs (
 revision bigserial PRIMARY KEY, content bytea NOT NULL, content_hash text NOT NULL,
 source text NOT NULL CHECK(source IN ('builtin','edited','imported')), publisher_signature text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS detector_health (
 organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE, device_id uuid NOT NULL,
 id uuid NOT NULL, payload jsonb NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,device_id,id), FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS candidate_domains (
 organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE, domain text NOT NULL,
 count bigint NOT NULL DEFAULT 0, first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(),
 status text NOT NULL DEFAULT 'new' CHECK(status IN ('new','ignored','promoted')),
 PRIMARY KEY(organization_id,domain)
);
-- Known platforms an organization chose not to see in Discovery. Presence keeps being
-- recorded: a platform the company sanctions is noise on that screen, not a fact to
-- erase, and unmuting must bring its history back rather than a blank slate. The row is
-- keyed by catalogue id, not by host, so a platform that gains or loses a domain stays
-- muted across catalogue revisions.
CREATE TABLE IF NOT EXISTS muted_platforms (
 organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE, platform_id text NOT NULL,
 muted_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,platform_id)
);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS collector_health jsonb NOT NULL DEFAULT '[]';
ALTER TABLE shadow_events ADD COLUMN IF NOT EXISTS detector text NOT NULL DEFAULT '';
ALTER TABLE shadow_events ADD COLUMN IF NOT EXISTS catalog_revision bigint;
ALTER TABLE shadow_events ADD COLUMN IF NOT EXISTS input_tokens bigint;
ALTER TABLE shadow_events ADD COLUMN IF NOT EXISTS output_tokens bigint;
ALTER TABLE shadow_events ADD COLUMN IF NOT EXISTS body_bytes bigint;
ALTER TABLE shadow_events ADD COLUMN IF NOT EXISTS characters_known boolean NOT NULL DEFAULT true;
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['detector_health','candidate_domains','muted_platforms'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename=t AND policyname='tenant') THEN
   EXECUTE format('CREATE POLICY tenant ON %I USING (organization_id=nullif(current_setting(''milvago.organization_id'',true),'''')::uuid) WITH CHECK (organization_id=nullif(current_setting(''milvago.organization_id'',true),'''')::uuid)',t);
  END IF;
 END LOOP;
END $$;
