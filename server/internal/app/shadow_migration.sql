CREATE SEQUENCE shadow_revision START 2;
ALTER TABLE devices ADD COLUMN capabilities jsonb NOT NULL DEFAULT '[]';
ALTER TABLE devices ADD COLUMN kind text NOT NULL DEFAULT 'browser' CHECK(kind IN ('browser','native'));
ALTER TABLE devices ADD COLUMN update_status text NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN update_reported_at timestamptz;
ALTER TABLE login_attempts ADD COLUMN association_org uuid;
ALTER TABLE login_attempts ADD COLUMN association_device uuid;
ALTER TABLE login_attempts ADD COLUMN association_hash bytea;
CREATE TABLE device_association_requests (
 organization_id uuid NOT NULL, device_id uuid NOT NULL, token_hash bytea NOT NULL PRIMARY KEY,
 expires_at timestamptz NOT NULL,
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id)
);
CREATE TABLE shadow_settings (
 organization_id uuid PRIMARY KEY REFERENCES organizations,
 revision bigint NOT NULL DEFAULT nextval('shadow_revision'),
 configuration jsonb NOT NULL DEFAULT '{}', inherit_sections jsonb NOT NULL DEFAULT '[]',
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE shadow_device_overrides (
 organization_id uuid NOT NULL, device_id uuid NOT NULL,
 revision bigint NOT NULL DEFAULT nextval('shadow_revision'), configuration jsonb NOT NULL,
 PRIMARY KEY(organization_id,device_id),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id)
);
CREATE TABLE collaborators (
 organization_id uuid NOT NULL REFERENCES organizations, id uuid NOT NULL DEFAULT gen_random_uuid(),
 subject text NOT NULL, display_name text NOT NULL, email text NOT NULL,
 PRIMARY KEY(organization_id,id), UNIQUE(organization_id,subject)
);
CREATE TABLE device_collaborators (
 organization_id uuid NOT NULL, device_id uuid NOT NULL, collaborator_id uuid NOT NULL,
 bound_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 PRIMARY KEY(organization_id,device_id),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id),
 FOREIGN KEY(organization_id,collaborator_id) REFERENCES collaborators(organization_id,id)
);
CREATE TABLE shadow_events (
 organization_id uuid NOT NULL REFERENCES organizations, device_id uuid NOT NULL, id uuid NOT NULL,
 occurred_at timestamptz NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
 kind text NOT NULL CHECK(kind IN ('navigation','prompt','response')),
 provider text NOT NULL, tool text NOT NULL, model text NOT NULL DEFAULT '', source text NOT NULL CHECK(source IN ('browser','native')),
 action text NOT NULL CHECK(action IN ('observed','blocked','redirected')),
 url text NOT NULL DEFAULT '', conversation_id text NOT NULL DEFAULT '', correlation_id text NOT NULL DEFAULT '', policy_revision bigint NOT NULL, collaborator_id uuid,
 characters integer NOT NULL CHECK(characters BETWEEN 0 AND 10000000), labels jsonb NOT NULL DEFAULT '[]',
 sensitivity text NOT NULL CHECK(sensitivity IN ('normal','sensitive','unknown')),
 PRIMARY KEY(organization_id,device_id,id),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id),
 FOREIGN KEY(organization_id,collaborator_id) REFERENCES collaborators(organization_id,id)
);
CREATE INDEX shadow_events_order ON shadow_events(organization_id,occurred_at DESC,id DESC,device_id DESC);
CREATE TABLE shadow_content (
 organization_id uuid NOT NULL, device_id uuid NOT NULL, event_id uuid NOT NULL,
 encrypted bytea NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(organization_id,device_id,event_id),
 FOREIGN KEY(organization_id,device_id,event_id) REFERENCES shadow_events(organization_id,device_id,id) ON DELETE CASCADE
);
CREATE INDEX shadow_content_expiry ON shadow_content(organization_id,expires_at);
CREATE TABLE shadow_saved_filters (
 organization_id uuid NOT NULL REFERENCES organizations, id uuid NOT NULL DEFAULT gen_random_uuid(),
 user_id uuid NOT NULL REFERENCES users, name text NOT NULL CHECK(length(name) BETWEEN 1 AND 120),
 filters jsonb NOT NULL, shared boolean NOT NULL DEFAULT false, updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['shadow_settings','shadow_device_overrides','collaborators','device_collaborators','shadow_events','shadow_content','shadow_saved_filters','device_association_requests'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON %I USING (current_user <> ''milvago_lookup'' AND organization_id=nullif(current_setting(''milvago.organization_id'',true),'''')::uuid) WITH CHECK (current_user <> ''milvago_lookup'' AND organization_id=nullif(current_setting(''milvago.organization_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
CREATE POLICY identity_lookup ON device_association_requests FOR SELECT TO milvago_lookup USING(current_user='milvago_lookup' AND encode(token_hash,'hex')=current_setting('milvago.lookup_hash',true));
CREATE FUNCTION association_identity(secret_hash bytea) RETURNS TABLE(organization_id uuid,device_id uuid) LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$ BEGIN
 PERFORM set_config('milvago.lookup_hash',encode(secret_hash,'hex'),true);
 RETURN QUERY SELECT a.organization_id,a.device_id FROM public.device_association_requests a WHERE a.token_hash=secret_hash AND a.expires_at>now();
 PERFORM set_config('milvago.lookup_hash','',true);
END $$;
REVOKE ALL ON FUNCTION association_identity(bytea) FROM PUBLIC;
GRANT CREATE ON SCHEMA public TO milvago_lookup;
GRANT SELECT ON device_association_requests TO milvago_lookup;
ALTER FUNCTION association_identity(bytea) OWNER TO milvago_lookup;
REVOKE CREATE ON SCHEMA public FROM milvago_lookup;
