CREATE TABLE IF NOT EXISTS ai_governance_policies (
 organization_id uuid PRIMARY KEY REFERENCES organizations ON DELETE CASCADE,
 revision bigint NOT NULL DEFAULT nextval('shadow_revision'),
 document jsonb NOT NULL DEFAULT '{"version":1,"rules":[]}',
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ai_governance_registry (
 organization_id uuid PRIMARY KEY REFERENCES organizations ON DELETE CASCADE,
 revision bigint NOT NULL DEFAULT nextval('shadow_revision'),
 document jsonb NOT NULL DEFAULT '{"version":1,"systems":[]}',
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ai_governance_exceptions (
 organization_id uuid NOT NULL, id uuid NOT NULL DEFAULT gen_random_uuid(),
 device_id uuid NOT NULL, rule_id text NOT NULL, policy_revision bigint NOT NULL,
 reason text NOT NULL, approved_by uuid NOT NULL REFERENCES users,
 approved_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 revoked_at timestamptz, PRIMARY KEY(organization_id,id),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ai_governance_exceptions_device ON ai_governance_exceptions(organization_id,device_id,policy_revision,expires_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ai_governance_exceptions_revision ON ai_governance_exceptions(organization_id,policy_revision,expires_at) WHERE revoked_at IS NULL;
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['ai_governance_policies','ai_governance_exceptions','ai_governance_registry'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname=current_schema() AND tablename=t AND policyname='ai_governance_tenant') THEN
   EXECUTE format('CREATE POLICY ai_governance_tenant ON %I USING (organization_id=nullif(current_setting(''milvago.organization_id'',true),'''')::uuid) WITH CHECK (organization_id=nullif(current_setting(''milvago.organization_id'',true),'''')::uuid)',t);
  END IF;
 END LOOP;
END $$;
