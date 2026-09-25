-- User-managed API credentials. One row per key; the plaintext is returned once at
-- creation and stored nowhere, so only its sha256 lives here.
--
-- A key is pinned to the organization that was active when it was created and to the
-- user who created it. Its `permissions` are a ceiling chosen at creation, never a
-- source of authority: every request re-derives the creator's live rights with
-- effective_access() and intersects, so demoting or removing the creator shrinks or
-- kills the key with no revocation sweep.
CREATE TABLE api_keys (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 -- ON DELETE CASCADE is spelled out so the foreign-key rewriting loop in db.go skips
 -- this constraint (it only touches those that are not already cascading) instead of
 -- dropping and recreating it on a boot.
 organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
 user_id uuid NOT NULL REFERENCES users,
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 60),
 secret_hash bytea NOT NULL UNIQUE CHECK(octet_length(secret_hash)=32),
 permissions text[] NOT NULL DEFAULT '{}' CHECK(cardinality(permissions) BETWEEN 1 AND 64),
 -- Reading prompt content is a separate, explicit opt-in: the creator's membership
 -- flag alone must not flow to a key that was only meant to read event metadata.
 content_access boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 revoked_at timestamptz, last_used_at timestamptz,
 -- The expiry ceiling lives here as well as in the handler, so no code path -- and no
 -- compromised runtime role -- can mint a key that outlives a year.
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '365 days')
);
CREATE INDEX api_keys_owner ON api_keys(organization_id,user_id,created_at DESC);
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON api_keys
 USING (current_user <> 'milvago_lookup' AND organization_id=nullif(current_setting('milvago.organization_id',true),'')::uuid)
 WITH CHECK (current_user <> 'milvago_lookup' AND organization_id=nullif(current_setting('milvago.organization_id',true),'')::uuid);
-- The one cross-tenant lookup. It returns the organization -- which is by necessity
-- unknowable before a tenant context exists -- and the row identity, and nothing else:
-- never the permissions, the owner, the name or the content flag. Authority is always
-- read back inside the tenant transaction, under row-level security.
--
-- What actually bounds this is not the WHERE clause but the api_key_lookup policy
-- below: milvago_lookup can see exactly one row, the one whose hash the definer body
-- just recorded. The WHERE clause is defence in depth.
CREATE FUNCTION api_key_identity(p_hash bytea)
RETURNS TABLE(organization_id uuid, key_id uuid) LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp
AS $$ BEGIN
 PERFORM set_config('milvago.lookup_hash',encode(p_hash,'hex'),true);
 RETURN QUERY SELECT k.organization_id,k.id FROM public.api_keys k
  WHERE k.secret_hash=p_hash AND k.revoked_at IS NULL AND k.expires_at>now();
 PERFORM set_config('milvago.lookup_hash','',true);
END $$;
REVOKE ALL ON FUNCTION api_key_identity(bytea) FROM PUBLIC;
CREATE POLICY api_key_lookup ON api_keys FOR SELECT TO milvago_lookup
 USING(current_user='milvago_lookup' AND encode(secret_hash,'hex')=current_setting('milvago.lookup_hash',true));
GRANT SELECT ON api_keys TO milvago_lookup;
-- Ownership must move to milvago_lookup for SECURITY DEFINER to reach the row behind
-- that policy. Owning an object in the schema needs CREATE for the duration of the
-- statement only: OpenDatabase refuses to boot if milvago_lookup keeps a durable
-- privilege, so the REVOKE is not cosmetic.
GRANT CREATE ON SCHEMA public TO milvago_lookup;
ALTER FUNCTION api_key_identity(bytea) OWNER TO milvago_lookup;
REVOKE CREATE ON SCHEMA public FROM milvago_lookup;
