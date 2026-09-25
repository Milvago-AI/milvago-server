CREATE TABLE IF NOT EXISTS privacy_settings (
 organization_id uuid PRIMARY KEY REFERENCES organizations ON DELETE CASCADE,
 revision bigint NOT NULL DEFAULT 1, configuration jsonb NOT NULL DEFAULT '{}',
 alias_key text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE collaborators ADD COLUMN IF NOT EXISTS alias text NOT NULL DEFAULT ('Subject '||upper(substr(replace(gen_random_uuid()::text,'-',''),1,16)));
ALTER TABLE collaborators ADD COLUMN IF NOT EXISTS subject_ciphertext text NOT NULL DEFAULT '';
ALTER TABLE collaborators ADD COLUMN IF NOT EXISTS team text NOT NULL DEFAULT '';
ALTER TABLE collaborators ADD COLUMN IF NOT EXISTS last_associated_at timestamptz NOT NULL DEFAULT now();
CREATE UNIQUE INDEX IF NOT EXISTS collaborators_alias ON collaborators(organization_id,alias);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS hostname_ciphertext text NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS mfa_verified_at timestamptz;
ALTER TABLE audit ADD COLUMN IF NOT EXISTS details jsonb NOT NULL DEFAULT '{}';
CREATE TABLE IF NOT EXISTS identity_reveals (
 organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
 id uuid NOT NULL DEFAULT gen_random_uuid(), session_hash bytea NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
 actor_id uuid NOT NULL REFERENCES users, collaborator_id uuid NOT NULL, privacy_revision bigint NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(organization_id,id),
 FOREIGN KEY(organization_id,collaborator_id) REFERENCES collaborators(organization_id,id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS subject_views (
 organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
 actor_id uuid NOT NULL REFERENCES users, subject text NOT NULL, view text NOT NULL, last_at timestamptz NOT NULL,
 PRIMARY KEY(organization_id,actor_id,subject,view)
);
CREATE TABLE IF NOT EXISTS aggregate_reports (
 organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
 week_start date NOT NULL, configuration_revision bigint NOT NULL, k integer NOT NULL, report jsonb NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(organization_id,week_start)
);
-- Retired 2026-09-14: the regulatory documentation feature (compliance settings and
-- generated PDF documents) was removed from the product. Existing databases drop the
-- orphaned table; its rows only ever held the configuration of that feature.
DROP TABLE IF EXISTS compliance_settings;
CREATE UNIQUE INDEX IF NOT EXISTS audit_organization_id ON audit(organization_id,id);
CREATE TABLE IF NOT EXISTS privacy_audit_outbox (
 organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
 audit_id uuid NOT NULL, configuration_key text NOT NULL,
 attempts integer NOT NULL DEFAULT 0, last_error text NOT NULL DEFAULT '', next_attempt timestamptz NOT NULL DEFAULT now(),
 -- pending: due for the active SIEM endpoint. held: queued for an endpoint that was
 -- disabled or replaced; never delivered elsewhere without a decision, resumed only
 -- if the same endpoint is enabled again. failed: retries exhausted, kept visible.
 state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','held','failed')),
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,audit_id), FOREIGN KEY(organization_id,audit_id) REFERENCES audit(organization_id,id) ON DELETE CASCADE
);
-- Convergence for databases created before the states existed.
ALTER TABLE privacy_audit_outbox ADD COLUMN IF NOT EXISTS state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','held','failed'));
ALTER TABLE privacy_audit_outbox ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['privacy_settings','identity_reveals','subject_views','aggregate_reports','privacy_audit_outbox'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename=t AND policyname='tenant') THEN
   EXECUTE format('CREATE POLICY tenant ON %I USING (organization_id=nullif(current_setting(''milvago.organization_id'',true),'''')::uuid) WITH CHECK (organization_id=nullif(current_setting(''milvago.organization_id'',true),'''')::uuid)',t);
  END IF;
 END LOOP;
END $$;
