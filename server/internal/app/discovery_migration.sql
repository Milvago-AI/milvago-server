CREATE TABLE IF NOT EXISTS discovery_settings (
 organization_id uuid PRIMARY KEY REFERENCES organizations ON DELETE CASCADE,
 revision bigint NOT NULL DEFAULT nextval('shadow_revision'),
 configuration jsonb NOT NULL DEFAULT '{"host":false,"containers":false,"virtual_machines":false,"guest_read":false,"guest_execute":false,"http":false,"network":false,"interval_seconds":300}',
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS discovery_catalogs (
 organization_id uuid PRIMARY KEY REFERENCES organizations ON DELETE CASCADE,
 revision bigint NOT NULL DEFAULT nextval('shadow_revision'),
 draft_revision bigint NOT NULL DEFAULT nextval('shadow_revision'),
 draft text NOT NULL DEFAULT '', content jsonb NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS discovery_scans (
 organization_id uuid NOT NULL, device_id uuid NOT NULL, scope text NOT NULL,
 sequence bigint NOT NULL, pages integer NOT NULL CHECK(pages BETWEEN 1 AND 256),
 received_pages integer[] NOT NULL DEFAULT '{}', observed_at timestamptz NOT NULL,
 complete boolean NOT NULL, finalized boolean NOT NULL DEFAULT false,
 page_hashes jsonb NOT NULL DEFAULT '{}',
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,device_id,scope),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS discovery_device_authorizations (
 organization_id uuid NOT NULL,device_id uuid NOT NULL,
 revision bigint NOT NULL DEFAULT nextval('shadow_revision'),
 fingerprint text NOT NULL,
 PRIMARY KEY(organization_id,device_id),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS discovery_entities (
 organization_id uuid NOT NULL, device_id uuid NOT NULL, scope text NOT NULL, id text NOT NULL,
 kind text NOT NULL, sequence bigint NOT NULL, first_seen timestamptz NOT NULL DEFAULT now(),
 last_seen timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL DEFAULT now()+interval '48 hours',
 PRIMARY KEY(organization_id,device_id,scope,id),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS discovery_entities_kind ON discovery_entities(organization_id,kind,last_seen DESC,id,device_id);
ALTER TABLE discovery_entities ADD COLUMN IF NOT EXISTS display jsonb NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS discovery_environments_order ON discovery_entities(organization_id,device_id,scope,id) WHERE kind<>'process';
CREATE TABLE IF NOT EXISTS discovery_identifications (
 organization_id uuid NOT NULL, device_id uuid NOT NULL, scope text NOT NULL, entity_id text NOT NULL,
 application_id text NOT NULL, signature_id text NOT NULL, signature_revision integer NOT NULL, state text NOT NULL,
 evidence jsonb NOT NULL, sequence bigint NOT NULL,
 first_seen timestamptz NOT NULL DEFAULT now(),last_seen timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL DEFAULT now()+interval '48 hours',
 PRIMARY KEY(organization_id,device_id,scope,entity_id,signature_id),
 FOREIGN KEY(organization_id,device_id,scope,entity_id) REFERENCES discovery_entities(organization_id,device_id,scope,id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS discovery_identifications_app ON discovery_identifications(organization_id,application_id,last_seen DESC,device_id);
CREATE INDEX IF NOT EXISTS discovery_instances_order ON discovery_identifications(organization_id,application_id,device_id,scope,entity_id,signature_id);
CREATE TABLE IF NOT EXISTS discovery_relations (
 organization_id uuid NOT NULL,device_id uuid NOT NULL,scope text NOT NULL,
 source_id text NOT NULL,target_id text NOT NULL,kind text NOT NULL,source text NOT NULL,
 sequence bigint NOT NULL,expires_at timestamptz NOT NULL DEFAULT now()+interval '48 hours',
 PRIMARY KEY(organization_id,device_id,scope,source_id,target_id,kind),
 FOREIGN KEY(organization_id,device_id,scope,source_id) REFERENCES discovery_entities(organization_id,device_id,scope,id) ON DELETE CASCADE,
 FOREIGN KEY(organization_id,device_id,scope,target_id) REFERENCES discovery_entities(organization_id,device_id,scope,id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS discovery_relations_target ON discovery_relations(organization_id,device_id,scope,target_id,source_id,kind);
CREATE TABLE IF NOT EXISTS discovery_coverage (
 organization_id uuid NOT NULL,device_id uuid NOT NULL,scope text NOT NULL,adapter text NOT NULL,
 status text NOT NULL,complete boolean NOT NULL,checked_at timestamptz NOT NULL,
 sequence bigint NOT NULL,expires_at timestamptz NOT NULL DEFAULT now()+interval '48 hours',
 PRIMARY KEY(organization_id,device_id,scope,adapter),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS discovery_events (
 organization_id uuid NOT NULL, id uuid NOT NULL DEFAULT gen_random_uuid(),device_id uuid NOT NULL,
 scope text NOT NULL,entity_id text NOT NULL,kind text NOT NULL,application_id text NOT NULL DEFAULT '',
 evidence jsonb NOT NULL DEFAULT '{}',occurred_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL DEFAULT now()+interval '30 days',
 PRIMARY KEY(organization_id,id),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS discovery_events_order ON discovery_events(organization_id,occurred_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS discovery_events_application ON discovery_events(organization_id,application_id,occurred_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS discovery_events_device_expiry ON discovery_events(organization_id,device_id,expires_at);
CREATE INDEX IF NOT EXISTS discovery_events_domain_query ON discovery_events(organization_id,device_id,scope,entity_id,(evidence->>'provider'),occurred_at) WHERE kind='provider_domain_queried';
CREATE TABLE IF NOT EXISTS discovery_communications (
 organization_id uuid NOT NULL,device_id uuid NOT NULL,scope text NOT NULL,entity_id text NOT NULL,
 provider text NOT NULL,sequence bigint NOT NULL,last_seen timestamptz NOT NULL,evidence jsonb NOT NULL,
 expires_at timestamptz NOT NULL DEFAULT now()+interval '48 hours',
 PRIMARY KEY(organization_id,device_id,scope,entity_id,provider),
 FOREIGN KEY(organization_id,device_id,scope,entity_id) REFERENCES discovery_entities(organization_id,device_id,scope,id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS discovery_reviews (
 organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE, application_id text NOT NULL,
 status text NOT NULL CHECK(status IN ('review','authorized','unauthorized','false_positive')),
 updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(organization_id,application_id)
);
CREATE TABLE IF NOT EXISTS discovery_runs (
 organization_id uuid NOT NULL,id uuid NOT NULL DEFAULT gen_random_uuid(),device_id uuid NOT NULL,
 status text NOT NULL CHECK(status IN ('pending','running','completed','cancelled','expired')),
 created_at timestamptz NOT NULL DEFAULT now(),expires_at timestamptz NOT NULL DEFAULT now()+interval '30 minutes',
 PRIMARY KEY(organization_id,id),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS discovery_runs_one_pending ON discovery_runs(organization_id,device_id) WHERE status IN ('pending','running');
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['discovery_settings','discovery_catalogs','discovery_scans','discovery_device_authorizations','discovery_entities','discovery_identifications','discovery_relations','discovery_coverage','discovery_events','discovery_communications','discovery_reviews','discovery_runs'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname=current_schema() AND tablename=t AND policyname='discovery_tenant') THEN
   EXECUTE format('CREATE POLICY discovery_tenant ON %I USING (organization_id=nullif(current_setting(''milvago.organization_id'',true),'''')::uuid) WITH CHECK (organization_id=nullif(current_setting(''milvago.organization_id'',true),'''')::uuid)',t);
  END IF;
 END LOOP;
END $$;
