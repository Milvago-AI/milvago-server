CREATE TABLE IF NOT EXISTS dlp_settings (
 organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
 domain text NOT NULL CHECK(domain='endpoint'),
 scope_kind text NOT NULL CHECK(scope_kind IN ('organization','group','device')),
 scope_id uuid NOT NULL,
 device_id uuid,
 group_id uuid,
 revision bigint NOT NULL DEFAULT nextval('shadow_revision'),
 inherited boolean NOT NULL DEFAULT false,
 policy jsonb NOT NULL CHECK(jsonb_typeof(policy)='object'),
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,domain,scope_kind,scope_id),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id) ON DELETE CASCADE,
 FOREIGN KEY(organization_id,group_id) REFERENCES device_groups(organization_id,id) ON DELETE CASCADE,
 CHECK((scope_kind='organization' AND scope_id=organization_id AND device_id IS NULL AND group_id IS NULL)
    OR (scope_kind='group' AND scope_id=group_id AND device_id IS NULL AND domain='endpoint')
    OR (scope_kind='device' AND scope_id=device_id AND group_id IS NULL AND domain='endpoint'))
);
CREATE TABLE IF NOT EXISTS dlp_policy_snapshots (
 organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
 fingerprint text NOT NULL CHECK(fingerprint ~ '^[0-9a-f]{64}$'),
 policy jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,fingerprint)
);
CREATE TABLE IF NOT EXISTS dlp_decisions (
 organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
 id uuid NOT NULL DEFAULT gen_random_uuid(),
 occurred_at timestamptz NOT NULL DEFAULT now(),
 channel text NOT NULL CHECK(channel IN ('browser','native')),
 policy_fingerprint text NOT NULL,
 device_id uuid,
 event_id uuid,
 action text NOT NULL CHECK(action IN ('observe','block','transform','review')),
 delivery text NOT NULL CHECK(delivery IN ('not_sent','prepared','observed','unknown','cancelled')),
 decisions jsonb NOT NULL CHECK(jsonb_typeof(decisions)='array'),
 expires_at timestamptz NOT NULL,
 PRIMARY KEY(organization_id,id),
 FOREIGN KEY(organization_id,policy_fingerprint) REFERENCES dlp_policy_snapshots(organization_id,fingerprint),
 FOREIGN KEY(organization_id,device_id,event_id) REFERENCES shadow_events(organization_id,device_id,id) ON DELETE CASCADE,
 UNIQUE(organization_id,device_id,event_id,policy_fingerprint)
);
CREATE INDEX IF NOT EXISTS dlp_decisions_time ON dlp_decisions(organization_id,occurred_at DESC,id);
CREATE INDEX IF NOT EXISTS dlp_decisions_event ON dlp_decisions(organization_id,device_id,event_id);
CREATE INDEX IF NOT EXISTS dlp_decisions_rules ON dlp_decisions USING gin(decisions jsonb_path_ops);
CREATE TABLE IF NOT EXISTS dlp_enforcement (
 organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
 device_id uuid NOT NULL,
 channel text NOT NULL CHECK(channel IN ('browser','native')),
 tool text NOT NULL,
 mechanism text NOT NULL,
 fingerprint text NOT NULL,
 status text NOT NULL CHECK(status IN ('applied','unavailable')),
 reported_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,device_id,channel,tool,mechanism),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS dlp_device_policy_history (
 organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
 device_id uuid NOT NULL,
 fingerprint text NOT NULL,
 revision bigint NOT NULL,
 delivered_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,device_id,fingerprint,revision),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id) ON DELETE CASCADE,
 FOREIGN KEY(organization_id,fingerprint) REFERENCES dlp_policy_snapshots(organization_id,fingerprint) ON DELETE CASCADE
);
CREATE SEQUENCE IF NOT EXISTS dlp_policy_revision;
CREATE TABLE IF NOT EXISTS dlp_device_policy_versions (
 organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
 device_id uuid NOT NULL,
 fingerprint text NOT NULL,
 revision bigint NOT NULL,
 PRIMARY KEY(organization_id,device_id),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id) ON DELETE CASCADE
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['dlp_settings','dlp_policy_snapshots','dlp_decisions','dlp_enforcement','dlp_device_policy_versions','dlp_device_policy_history'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename=t AND policyname='tenant') THEN
   EXECUTE format('CREATE POLICY tenant ON %I USING (organization_id=nullif(current_setting(''milvago.organization_id'',true),'''')::uuid) WITH CHECK (organization_id=nullif(current_setting(''milvago.organization_id'',true),'''')::uuid)',t);
  END IF;
 END LOOP;
END $$;

ALTER TABLE dlp_settings ADD COLUMN IF NOT EXISTS default_rule_ids jsonb NOT NULL DEFAULT '[]'::jsonb
 CHECK(jsonb_typeof(default_rule_ids)='array' AND jsonb_array_length(default_rule_ids)<=128);
