-- E-mail domains an organization claims for single sign-on. A domain routes sign-ins and
-- invitations only once proven through DNS, and a proven domain names one organization.
CREATE TABLE IF NOT EXISTS sso_domains (
 organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
 domain text NOT NULL CHECK (length(domain) BETWEEN 3 AND 253 AND domain = lower(domain)),
 challenge text NOT NULL CHECK (length(challenge) BETWEEN 32 AND 64),
 verified_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (organization_id, domain)
);
CREATE UNIQUE INDEX IF NOT EXISTS sso_domains_proven ON sso_domains(domain) WHERE verified_at IS NOT NULL;
ALTER TABLE sso_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso_domains FORCE ROW LEVEL SECURITY;
CREATE OR REPLACE FUNCTION public.sso_domain_lookup_role() RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT current_user = 'milvago_lookup'
$$;
DROP POLICY IF EXISTS tenant ON sso_domains;
CREATE POLICY tenant ON sso_domains USING (NOT public.sso_domain_lookup_role() AND organization_id = nullif(current_setting('milvago.organization_id',true),'')::uuid) WITH CHECK (NOT public.sso_domain_lookup_role() AND organization_id = nullif(current_setting('milvago.organization_id',true),'')::uuid);
-- The unauthenticated sign-in reads which organization proved one domain, nothing else.
DROP POLICY IF EXISTS identity_lookup ON sso_domains;
CREATE POLICY identity_lookup ON sso_domains FOR SELECT TO milvago_lookup USING (public.sso_domain_lookup_role() AND verified_at IS NOT NULL AND domain = current_setting('milvago.lookup_domain',true));
-- Keep the lookup domain scoped to this transaction and share the exact
-- setting name between setup and cleanup.
CREATE OR REPLACE FUNCTION public.set_sso_lookup_domain(wanted text) RETURNS text LANGUAGE sql VOLATILE AS $$
 SELECT set_config('milvago.lookup_domain', wanted, true)
$$;
REVOKE ALL ON FUNCTION public.set_sso_lookup_domain(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.set_sso_lookup_domain(text) TO milvago_lookup;
CREATE OR REPLACE FUNCTION sso_domain_owner(wanted text) RETURNS TABLE(organization_id uuid) LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$ BEGIN
 PERFORM public.set_sso_lookup_domain(lower(wanted));
 RETURN QUERY SELECT d.organization_id FROM public.sso_domains d WHERE d.domain = lower(wanted) AND d.verified_at IS NOT NULL;
 PERFORM public.set_sso_lookup_domain('');
END $$;
REVOKE ALL ON FUNCTION sso_domain_owner(text) FROM PUBLIC;
GRANT CREATE ON SCHEMA public TO milvago_lookup;
GRANT SELECT ON sso_domains TO milvago_lookup;
ALTER FUNCTION sso_domain_owner(text) OWNER TO milvago_lookup;
REVOKE CREATE ON SCHEMA public FROM milvago_lookup;
