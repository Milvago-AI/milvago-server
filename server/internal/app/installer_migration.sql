CREATE TABLE installer_profiles (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations,
 secret_hash bytea NOT NULL UNIQUE CHECK(octet_length(secret_hash)=32), secret_ciphertext text NOT NULL,
 edition text NOT NULL CHECK(edition IN ('community','commercial')),
 platform text NOT NULL CHECK(platform IN ('windows','linux')), version text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 max_uses integer NOT NULL CHECK(max_uses BETWEEN 1 AND 10000), uses integer NOT NULL DEFAULT 0 CHECK(uses>=0),
 revoked boolean NOT NULL DEFAULT false, configuration jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(configuration)='object'),
 UNIQUE(organization_id,id), CHECK(uses<=max_uses), CHECK(expires_at<=created_at+interval '30 days')
);
CREATE TABLE installer_installations (
 organization_id uuid NOT NULL, profile_id uuid NOT NULL, installation_id uuid NOT NULL,
 installation_secret_hash bytea NOT NULL CHECK(octet_length(installation_secret_hash)=32),
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
 device_id uuid NOT NULL, credential_ciphertext text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,profile_id,installation_id), UNIQUE(organization_id,device_id),
 FOREIGN KEY(organization_id,profile_id) REFERENCES installer_profiles(organization_id,id),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['installer_profiles','installer_installations'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON %I USING (current_user <> ''milvago_lookup'' AND organization_id=nullif(current_setting(''milvago.organization_id'',true),'''')::uuid) WITH CHECK (current_user <> ''milvago_lookup'' AND organization_id=nullif(current_setting(''milvago.organization_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
CREATE FUNCTION installer_identity(p_hash bytea)
RETURNS TABLE(organization_id uuid) LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp
AS $$ BEGIN
 PERFORM set_config('milvago.lookup_hash',encode(p_hash,'hex'),true);
 RETURN QUERY SELECT p.organization_id FROM public.installer_profiles p WHERE p.secret_hash=p_hash AND NOT p.revoked AND p.expires_at>now();
 PERFORM set_config('milvago.lookup_hash','',true);
END $$;
REVOKE ALL ON FUNCTION installer_identity(bytea) FROM PUBLIC;
CREATE POLICY installer_lookup ON installer_profiles FOR SELECT TO milvago_lookup
 USING(current_user='milvago_lookup' AND encode(secret_hash,'hex')=current_setting('milvago.lookup_hash',true));
GRANT SELECT ON installer_profiles TO milvago_lookup;
GRANT CREATE ON SCHEMA public TO milvago_lookup;
ALTER FUNCTION installer_identity(bytea) OWNER TO milvago_lookup;
REVOKE CREATE ON SCHEMA public FROM milvago_lookup;
