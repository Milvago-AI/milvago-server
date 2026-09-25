CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY);
CREATE TABLE IF NOT EXISTS organizations (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120), parent_id uuid REFERENCES organizations
);
CREATE TABLE IF NOT EXISTS app_config (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton), organization_id uuid NOT NULL REFERENCES organizations,
 bootstrap_email text NOT NULL, bootstrap_consumed boolean NOT NULL DEFAULT false
);
ALTER TABLE app_config ADD COLUMN IF NOT EXISTS public_url text NOT NULL DEFAULT '';
ALTER TABLE app_config ADD COLUMN IF NOT EXISTS public_url_confirmed boolean NOT NULL DEFAULT false;
ALTER TABLE app_config ADD COLUMN IF NOT EXISTS default_language text NOT NULL DEFAULT 'fr';
-- The instance licence, a signed JWT verified on every read (license.go).
ALTER TABLE app_config ADD COLUMN IF NOT EXISTS license text NOT NULL DEFAULT '';
-- Dropped and re-added rather than declared inline: an inline CHECK is only
-- applied when the column is created, so widening the language set would never
-- reach a database that already has the column.
ALTER TABLE app_config DROP CONSTRAINT IF EXISTS app_config_default_language_check;
ALTER TABLE app_config ADD CONSTRAINT app_config_default_language_check CHECK (default_language IN ('fr','en','es','pt-BR'));
CREATE TABLE IF NOT EXISTS users (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), subject text NOT NULL UNIQUE,
 email text NOT NULL, display_name text NOT NULL
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS identity_type text NOT NULL DEFAULT 'local';
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_identity_type_check;
ALTER TABLE users ADD CONSTRAINT users_identity_type_check CHECK (identity_type IN ('local','sso','ldap'));
-- Console language of one account; empty means "follow the instance default".
ALTER TABLE users ADD COLUMN IF NOT EXISTS language text NOT NULL DEFAULT '';
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_language_check;
ALTER TABLE users ADD CONSTRAINT users_language_check CHECK (language IN ('','fr','en','es','pt-BR'));
CREATE TABLE IF NOT EXISTS memberships (
 organization_id uuid NOT NULL REFERENCES organizations, user_id uuid NOT NULL REFERENCES users,
 role text NOT NULL, PRIMARY KEY (organization_id,user_id)
);
-- Custom-role model: each organization owns its role definitions (built-ins seeded per org).
CREATE TABLE IF NOT EXISTS roles (
 organization_id uuid NOT NULL REFERENCES organizations, name text NOT NULL CHECK (length(name) BETWEEN 1 AND 60),
 permissions text[] NOT NULL DEFAULT '{}', builtin boolean NOT NULL DEFAULT false, PRIMARY KEY (organization_id,name)
);
-- A membership role must be a role defined for its organization.
CREATE OR REPLACE FUNCTION validate_membership_role() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM roles r WHERE r.organization_id=NEW.organization_id AND r.name=NEW.role) THEN
  RAISE EXCEPTION 'unknown role % for organization', NEW.role;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS membership_role_valid ON memberships;
CREATE TRIGGER membership_role_valid BEFORE INSERT OR UPDATE ON memberships FOR EACH ROW EXECUTE FUNCTION validate_membership_role();
-- Existing databases carry the former fixed-role CHECK; drop it so custom roles are accepted.
ALTER TABLE memberships DROP CONSTRAINT IF EXISTS memberships_role_check;
CREATE TABLE IF NOT EXISTS sessions (
 token_hash bytea PRIMARY KEY, user_id uuid NOT NULL REFERENCES users, organization_id uuid NOT NULL REFERENCES organizations,
 csrf_token text NOT NULL, encrypted_tokens bytea NOT NULL, mfa boolean NOT NULL DEFAULT false,
 expires_at timestamptz NOT NULL
);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS identity_expires_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS oidc_nonce text NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS login_attempts (
 state_hash bytea PRIMARY KEY, binding_hash bytea NOT NULL, verifier text NOT NULL, nonce text NOT NULL, expires_at timestamptz NOT NULL
);
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS step_up boolean NOT NULL DEFAULT false;
-- First-run setup wizard (setup.go): short sessions opened by the setup token.
-- Instance-level, like login_attempts: no organization owns them yet.
CREATE TABLE IF NOT EXISTS setup_sessions (
 id_hash bytea PRIMARY KEY, csrf text NOT NULL, expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
 organization_id uuid PRIMARY KEY REFERENCES organizations, retention_days integer NOT NULL DEFAULT 90 CHECK (retention_days BETWEEN 1 AND 365),
 require_mfa boolean NOT NULL DEFAULT false
);
-- Detailed events live at most min(retention_days, identity_link_days) days. Both
-- default to 90 so the default identity link is effective, not nominal.
ALTER TABLE settings ALTER COLUMN retention_days SET DEFAULT 90;
CREATE TABLE IF NOT EXISTS policies (
 organization_id uuid PRIMARY KEY REFERENCES organizations, revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
 rules jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(rules)='array'), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS enrollments (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations,
 token_hash bytea NOT NULL UNIQUE, label text NOT NULL, expires_at timestamptz NOT NULL, consumed_at timestamptz
);
CREATE TABLE IF NOT EXISTS devices (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations,
 credential_hash bytea NOT NULL UNIQUE, hostname text NOT NULL, platform text NOT NULL, version text NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','revoked')),
 last_seen timestamptz, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(organization_id,id)
);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_user text NOT NULL DEFAULT '';
-- Browsers whose extension reported to the local agent, and when. Informational,
-- like os_user: it distinguishes "no AI use" from "no longer supervised".
ALTER TABLE devices ADD COLUMN IF NOT EXISTS browsers jsonb NOT NULL DEFAULT '{}'::jsonb;
-- Domains the machine declared at enrollment (Active Directory, Entra tenant, Linux realm):
-- shown to whoever approves it and matched by approval rules, never proof of membership.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS machine_domains jsonb NOT NULL DEFAULT '[]'::jsonb;
CREATE TABLE IF NOT EXISTS events (
 organization_id uuid NOT NULL REFERENCES organizations, device_id uuid NOT NULL,
 id uuid NOT NULL, occurred_at timestamptz NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
 provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 100), action text NOT NULL CHECK(action IN ('observed','blocked')),
 source text NOT NULL CHECK(source='browser'), characters integer NOT NULL CHECK(characters BETWEEN 0 AND 10000000),
 labels jsonb NOT NULL CHECK(jsonb_typeof(labels)='array'), PRIMARY KEY(organization_id,device_id,id),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id)
);
CREATE INDEX IF NOT EXISTS events_order ON events(organization_id,occurred_at DESC,id DESC,device_id DESC);
CREATE TABLE IF NOT EXISTS audit (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations,
 occurred_at timestamptz NOT NULL DEFAULT now(), actor text NOT NULL, action text NOT NULL, target text NOT NULL
);
-- Which API key performed the action, when it was not an interactive session.
-- Nullable: a console session leaves it NULL. Deliberately NOT a foreign key -- the
-- cascade loop in db.go rewrites every single-column foreign key to ON DELETE CASCADE,
-- and a cascade into audit is refused by the append-only trigger below, which would
-- make the hourly purge of a retired key fail permanently.
ALTER TABLE audit ADD COLUMN IF NOT EXISTS api_key_id uuid;
-- Which OAuth client performed the action, when it came through an access token on
-- the MCP endpoint (Enterprise). NULL for a console session and for an API key: a
-- prompt read by a connector must not look like the same person reading it on screen.
ALTER TABLE audit ADD COLUMN IF NOT EXISTS oauth_client text;
-- The reading order of GET /api/audit, which is `ORDER BY occurred_at DESC,id DESC
-- LIMIT 200` under the tenant policy. The only other index on this table is the
-- UNIQUE(organization_id,id) the privacy outbox foreign key needs, which says nothing
-- about that order. The two sibling tables with the same access pattern -- events and
-- shadow_events -- both carry this index already; audit did not, and it is written on
-- nearly every mutating request and kept 730 days by the trigger below, so it only
-- ever grows. Declared here rather than in shadow_migration.sql because this file runs
-- unconditionally on every boot and therefore reaches databases already migrated.
CREATE INDEX IF NOT EXISTS audit_order ON audit(organization_id,occurred_at DESC,id DESC);
CREATE OR REPLACE FUNCTION reject_audit_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 -- Audit is append only. Two exceptions, each signalled by a transaction-local
 -- flag so an accidental DELETE still fails. Updates are never allowed.
 -- 1. The cascade purge of a deleted organization's own rows, flagged with the
 --    target org id by the organization-deletion handler.
 --    The organization row must already be gone: the flag alone is a setting the
 --    runtime role can set itself, which let it delete any recent audit row of its
 --    tenant without deleting anything else (audit of 2026-09-24).
 IF TG_OP = 'DELETE' AND current_setting('milvago.purge_org', true) = OLD.organization_id::text
  AND NOT EXISTS (SELECT 1 FROM public.organizations WHERE id = OLD.organization_id) THEN
  RETURN OLD;
 END IF;
 -- 2. Retention. The 730-day floor is enforced here rather than only in the
 --    caller, so no code path — and no compromised runtime role — can delete a
 --    recent audit row by choosing its own cutoff.
 IF TG_OP = 'DELETE'
  AND coalesce(current_setting('milvago.purge_audit_before', true),'') <> ''
  AND OLD.occurred_at < current_setting('milvago.purge_audit_before', true)::timestamptz
  AND OLD.occurred_at < now()-interval '730 days' THEN
  RETURN OLD;
 END IF;
 RAISE EXCEPTION 'audit is append only';
END $$;
DROP TRIGGER IF EXISTS audit_append_only ON audit;
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit FOR EACH ROW EXECUTE FUNCTION reject_audit_change();

-- The only cross-tenant lookups bind a high-entropy secret hash to its stored organization.
-- SECURITY DEFINER is confined to these read-only functions and a fixed schema search path.
CREATE OR REPLACE FUNCTION enrollment_identity(secret_hash bytea)
RETURNS TABLE(organization_id uuid) LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp
AS $$ BEGIN
 PERFORM set_config('milvago.lookup_hash',encode(secret_hash,'hex'),true);
 RETURN QUERY SELECT e.organization_id FROM public.enrollments e WHERE e.token_hash=secret_hash AND e.consumed_at IS NULL AND e.expires_at>now();
 PERFORM set_config('milvago.lookup_hash','',true);
END $$;
CREATE OR REPLACE FUNCTION device_identity(secret_hash bytea)
RETURNS TABLE(organization_id uuid, device_id uuid) LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp
AS $$ BEGIN
 PERFORM set_config('milvago.lookup_hash',encode(secret_hash,'hex'),true);
 RETURN QUERY SELECT d.organization_id,d.id FROM public.devices d WHERE d.credential_hash=secret_hash AND d.status='approved';
 PERFORM set_config('milvago.lookup_hash','',true);
END $$;
REVOKE ALL ON FUNCTION enrollment_identity(bytea),device_identity(bytea) FROM PUBLIC;
-- Organizations a user may act in: direct memberships plus all descendant orgs
-- (a parent membership grants access down the tree). Role per org = the nearest
-- ancestor membership's role (a direct membership wins over an inherited one).
CREATE OR REPLACE FUNCTION user_organizations(identity_id uuid)
RETURNS TABLE(id uuid,name text,role text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp
AS $$ BEGIN
 PERFORM set_config('milvago.lookup_user',identity_id::text,true);
 RETURN QUERY
  WITH RECURSIVE tree(org,role,depth) AS (
   SELECT m.organization_id,m.role,0 FROM public.memberships m WHERE m.user_id=identity_id
   UNION ALL
   SELECT o.id,t.role,t.depth+1 FROM public.organizations o JOIN tree t ON o.parent_id=t.org
  )
  SELECT o.id,o.name,best.role FROM (
   SELECT DISTINCT ON (t.org) t.org,t.role FROM tree t ORDER BY t.org,t.depth
  ) best JOIN public.organizations o ON o.id=best.org ORDER BY o.name,o.id;
 PERFORM set_config('milvago.lookup_user','',true);
END $$;
REVOKE ALL ON FUNCTION user_organizations(uuid) FROM PUBLIC;
-- Effective (source org, role, permissions) for a user acting in target_org: the
-- direct membership, else the nearest ancestor membership (hierarchy access).
CREATE OR REPLACE FUNCTION effective_access(identity_id uuid, target_org uuid)
RETURNS TABLE(source_org uuid, role text, permissions text[]) LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp
AS $$ DECLARE src uuid; rle text; pin text; BEGIN
 -- An API key is pinned to the organization it was created in. The pin is set
 -- transaction-local by the API key wrapper, so every authorization decision that
 -- goes through this function fails closed outside that organization -- including the
 -- ones handlers make for an organization named in the request path
 -- (targetOrganization, renameOrganization, deleteOrganization, createOrganization's
 -- parent) and the ones routes written later will make. Enforcing it here rather than
 -- at each call site is what makes it fail closed by default instead of relying on
 -- every future author remembering. Inert for cookie sessions: the setting is empty.
 pin := coalesce(current_setting('milvago.api_key_org',true),'');
 IF pin <> '' AND pin <> target_org::text THEN
  RETURN;
 END IF;
 PERFORM set_config('milvago.lookup_user',identity_id::text,true);
 WITH RECURSIVE chain(org,depth) AS (
  SELECT target_org,0
  UNION ALL
  SELECT o.parent_id,c.depth+1 FROM public.organizations o JOIN chain c ON o.id=c.org WHERE o.parent_id IS NOT NULL
 )
 SELECT c.org,m.role INTO src,rle
 FROM chain c JOIN public.memberships m ON m.organization_id=c.org AND m.user_id=identity_id
 ORDER BY c.depth ASC LIMIT 1;
 IF src IS NOT NULL THEN
  RETURN QUERY SELECT src,rle,COALESCE((SELECT r.permissions FROM public.roles r WHERE r.organization_id=src AND r.name=rle),'{}'::text[]);
 END IF;
 PERFORM set_config('milvago.lookup_user','',true);
END $$;
REVOKE ALL ON FUNCTION effective_access(uuid,uuid) FROM PUBLIC;
-- Members of an org and all its descendants (for the Members subtree listing).
-- Only returns rows when the caller has members.read effective in root_org.
-- Reading retained text is the `content.read` permission of a role, not a per-member
-- flag (product decision, 2026-09-15). The column is dropped here because this file runs
-- on every boot: shadow_migration.sql is pinned by schema_migrations version 2 and is
-- never replayed, so editing it alone would leave the column on every existing
-- database. Idempotent, like the compliance_settings drop in privacy_migration.sql.
ALTER TABLE memberships DROP COLUMN IF EXISTS content_access;
DROP FUNCTION IF EXISTS subtree_members(uuid,uuid);
CREATE OR REPLACE FUNCTION subtree_members(identity_id uuid, root_org uuid)
RETURNS TABLE(organization_id uuid, organization_name text, member_id uuid, email text, display_name text, role text, identity_type text, language text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp
AS $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM effective_access(identity_id,root_org) WHERE 'members.read'=ANY(permissions)) THEN
  RETURN;
 END IF;
 PERFORM set_config('milvago.lookup_subtree','1',true);
 RETURN QUERY
  WITH RECURSIVE sub(org) AS (
   SELECT root_org
   UNION ALL
   SELECT o.id FROM public.organizations o JOIN sub s ON o.parent_id=s.org
  )
  SELECT o.id,o.name,u.id,u.email,u.display_name,m.role,u.identity_type,u.language
  FROM sub s JOIN public.organizations o ON o.id=s.org
  JOIN public.memberships m ON m.organization_id=o.id
  JOIN public.users u ON u.id=m.user_id
  ORDER BY o.name,u.email;
 PERFORM set_config('milvago.lookup_subtree','',true);
END $$;
REVOKE ALL ON FUNCTION subtree_members(uuid,uuid) FROM PUBLIC;

-- Per-organization LDAP directory (Keycloak user-federation component). The bind
-- credential is held by Keycloak only and never stored here.
CREATE TABLE IF NOT EXISTS ldap_directories (
 organization_id uuid PRIMARY KEY REFERENCES organizations, component_id text NOT NULL UNIQUE,
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
 vendor text NOT NULL CHECK (vendor IN ('ad','rhds','tivoli','edirectory','other')),
 connection_url text NOT NULL, bind_dn text NOT NULL DEFAULT '', users_dn text NOT NULL,
 username_attribute text NOT NULL, rdn_attribute text NOT NULL, uuid_attribute text NOT NULL, user_object_classes text NOT NULL,
 custom_filter text NOT NULL DEFAULT '', search_scope integer NOT NULL CHECK (search_scope IN (1,2)),
 auth_type text NOT NULL CHECK (auth_type IN ('simple','none')), start_tls boolean NOT NULL DEFAULT false,
 use_truststore text NOT NULL CHECK (use_truststore IN ('always','never')),
 connection_timeout_ms integer NOT NULL CHECK (connection_timeout_ms BETWEEN 0 AND 300000),
 read_timeout_ms integer NOT NULL CHECK (read_timeout_ms BETWEEN 0 AND 300000),
 pagination boolean NOT NULL DEFAULT true, updated_at timestamptz NOT NULL DEFAULT now()
);

DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['memberships','roles','settings','policies','enrollments','devices','events','audit','ldap_directories'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('DROP POLICY IF EXISTS tenant ON %I',t);
  EXECUTE format('CREATE POLICY tenant ON %I USING (current_user <> ''milvago_lookup'' AND organization_id = nullif(current_setting(''milvago.organization_id'',true),'''')::uuid) WITH CHECK (current_user <> ''milvago_lookup'' AND organization_id = nullif(current_setting(''milvago.organization_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
DROP POLICY IF EXISTS identity_lookup ON enrollments;
CREATE POLICY identity_lookup ON enrollments FOR SELECT TO milvago_lookup USING(current_user='milvago_lookup' AND encode(token_hash,'hex')=current_setting('milvago.lookup_hash',true));
DROP POLICY IF EXISTS identity_lookup ON devices;
CREATE POLICY identity_lookup ON devices FOR SELECT TO milvago_lookup USING(current_user='milvago_lookup' AND encode(credential_hash,'hex')=current_setting('milvago.lookup_hash',true));
DROP POLICY IF EXISTS identity_lookup ON memberships;
CREATE POLICY identity_lookup ON memberships FOR SELECT TO milvago_lookup USING(current_user='milvago_lookup' AND user_id=nullif(current_setting('milvago.lookup_user',true),'')::uuid);
-- Subtree member listing reads memberships across the accessible subtree; guarded
-- by a marker only the SECURITY DEFINER subtree_members function sets.
DROP POLICY IF EXISTS subtree_lookup ON memberships;
CREATE POLICY subtree_lookup ON memberships FOR SELECT TO milvago_lookup USING(current_user='milvago_lookup' AND current_setting('milvago.lookup_subtree',true)<>'');
-- Role permission lists are read cross-org by the resolver functions (no secrets).
DROP POLICY IF EXISTS identity_lookup ON roles;
CREATE POLICY identity_lookup ON roles FOR SELECT TO milvago_lookup USING(current_user='milvago_lookup' AND current_setting('milvago.lookup_user',true)<>'');
GRANT USAGE,CREATE ON SCHEMA public TO milvago_lookup;
GRANT SELECT ON enrollments,devices,memberships,organizations,roles,users TO milvago_lookup;
ALTER FUNCTION enrollment_identity(bytea) OWNER TO milvago_lookup;
ALTER FUNCTION device_identity(bytea) OWNER TO milvago_lookup;
ALTER FUNCTION user_organizations(uuid) OWNER TO milvago_lookup;
ALTER FUNCTION effective_access(uuid,uuid) OWNER TO milvago_lookup;
ALTER FUNCTION subtree_members(uuid,uuid) OWNER TO milvago_lookup;
REVOKE CREATE ON SCHEMA public FROM milvago_lookup;
INSERT INTO schema_migrations(version) VALUES(1) ON CONFLICT DO NOTHING;
