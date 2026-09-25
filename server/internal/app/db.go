package app

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migration.sql
var migration string

//go:embed shadow_migration.sql
var shadowMigration string

//go:embed privacy_migration.sql
var privacyMigration string

func OpenDatabase(ctx context.Context, c Config) (*pgxpool.Pool, error) {
	m, e := pgxpool.New(ctx, c.MigrationURL)
	if e != nil {
		return nil, e
	}
	defer m.Close()
	tx, e := m.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(726403210)`); e != nil {
		return nil, e
	}
	var unsafeLookup bool
	if e = tx.QueryRow(ctx, `SELECT rolcanlogin OR rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb FROM pg_roles WHERE rolname='milvago_lookup'`).Scan(&unsafeLookup); e != nil || unsafeLookup {
		return nil, errors.New("milvago_lookup must exist as NOLOGIN, non-superuser, NOBYPASSRLS, NOCREATEROLE and NOCREATEDB")
	}
	if _, e = tx.Exec(ctx, migration); e != nil {
		return nil, fmt.Errorf("migration: %w", e)
	}
	if editionMigration != "" {
		if _, e = tx.Exec(ctx, editionMigration); e != nil {
			return nil, fmt.Errorf("edition migration: %w", e)
		}
	}
	var shadowApplied bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=2)`).Scan(&shadowApplied); e != nil {
		return nil, e
	}
	if !shadowApplied {
		if _, e = tx.Exec(ctx, shadowMigration); e != nil {
			return nil, fmt.Errorf("shadow migration: %w", e)
		}
		if _, e = tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES(2)`); e != nil {
			return nil, e
		}
	}
	if _, e = tx.Exec(ctx, `INSERT INTO organizations(name) SELECT $1 WHERE NOT EXISTS(SELECT 1 FROM organizations)`, c.OrganizationName); e != nil {
		return nil, e
	}
	if Edition == "community" {
		var count int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM organizations`).Scan(&count); e != nil {
			return nil, e
		}
		if count != 1 {
			return nil, errors.New("Community cannot open a multi-organization database")
		}
	}
	if _, e = tx.Exec(ctx, `INSERT INTO app_config(organization_id,bootstrap_email,public_url) SELECT id,$1,$2 FROM organizations ORDER BY id LIMIT 1 ON CONFLICT(singleton) DO NOTHING`, c.BootstrapEmail, c.PublicURL); e != nil {
		return nil, e
	}
	if e = initializeEdition(ctx, tx); e != nil {
		return nil, fmt.Errorf("edition initialization: %w", e)
	}
	if _, e = tx.Exec(ctx, `DO $$ DECLARE org uuid; BEGIN FOR org IN SELECT id FROM organizations LOOP PERFORM set_config('milvago.organization_id',org::text,true); INSERT INTO settings(organization_id) VALUES(org) ON CONFLICT DO NOTHING; INSERT INTO policies(organization_id) VALUES(org) ON CONFLICT DO NOTHING; INSERT INTO roles(organization_id,name,permissions,builtin) VALUES (org,'owner',ARRAY['overview.read','events.read','devices.read','devices.manage','members.read','members.manage','settings.manage','policy.manage','installers.manage','content.read','audit.read','roles.manage','organizations.manage','directory.manage'],true),(org,'admin',ARRAY['overview.read','events.read','devices.read','devices.manage','members.read','members.manage','settings.manage','policy.manage','installers.manage','content.read'],true),(org,'viewer',ARRAY['overview.read','events.read','devices.read'],true) ON CONFLICT (organization_id,name) DO UPDATE SET permissions=EXCLUDED.permissions WHERE roles.builtin; UPDATE memberships SET role='viewer' WHERE role='analyst'; END LOOP; PERFORM set_config('milvago.organization_id','',true); END $$`); e != nil {
		return nil, e
	}
	// Names of the files attached to a request. Applied here rather than in the base
	// migration because shadow_events is created by the shadow migration, which runs
	// once; this statement is idempotent and reaches databases created before it.
	if _, e = tx.Exec(ctx, `ALTER TABLE shadow_events ADD COLUMN IF NOT EXISTS files jsonb NOT NULL DEFAULT '[]'::jsonb`); e != nil {
		return nil, e
	}
	// When an AI application was first observed on a device. Added here because the
	// table is created by the edition migration, which existing databases already
	// applied; without a first sighting, an inventory can only answer "now".
	if Edition == "commercial" {
		if _, e = tx.Exec(ctx, `ALTER TABLE tool_observations ADD COLUMN IF NOT EXISTS first_seen timestamptz NOT NULL DEFAULT now()`); e != nil {
			return nil, e
		}
		// The vocabulary of AI applications now comes from the signed catalog. A CHECK
		// listing six names meant adding a tool required a migration, which is exactly
		// what the catalog exists to avoid. Shape is still constrained.
		if _, e = tx.Exec(ctx, `ALTER TABLE tool_observations DROP CONSTRAINT IF EXISTS tool_observations_tool_check;
			ALTER TABLE tool_observations DROP CONSTRAINT IF EXISTS tool_observations_kind_check;
			ALTER TABLE tool_observations ADD CONSTRAINT tool_observations_tool_check CHECK(tool ~ '^[a-z0-9][a-z0-9._-]{0,63}$');
			ALTER TABLE tool_observations ADD CONSTRAINT tool_observations_kind_check CHECK(kind IN ('executable','process','installed','extension','port'))`); e != nil {
			return nil, e
		}
	}
	// Profile a native record was collected from, on a shared machine.
	if _, e = tx.Exec(ctx, `ALTER TABLE shadow_events ADD COLUMN IF NOT EXISTS "user" text NOT NULL DEFAULT ''`); e != nil {
		return nil, e
	}
	// The same account, as a per-organization digest that groups. The account
	// itself is sealed under a key that includes the event identifier, so two
	// records of one person never share a ciphertext and no aggregate can group
	// by it: the cartography could only ever answer "unattributed" for everyone
	// it had no verified association for. This column is the groupable pseudonym;
	// the readable account still comes from the sealed value through the reveal
	// path. Records written before this column keep an empty digest and stay
	// unattributed on the map — their sealed accounts are not re-digested.
	if _, e = tx.Exec(ctx, `ALTER TABLE shadow_events ADD COLUMN IF NOT EXISTS user_key text NOT NULL DEFAULT ''`); e != nil {
		return nil, e
	}
	// The reasoning effort a provider was asked for. Kept in its own column rather
	// than folded into the model: the two are separate settings on the provider
	// side, and merging them would split one model into as many rows as it has
	// effort levels in every count.
	if _, e = tx.Exec(ctx, `ALTER TABLE shadow_events ADD COLUMN IF NOT EXISTS effort text NOT NULL DEFAULT ''`); e != nil {
		return nil, e
	}
	// Conversation reading groups records by thread and recovers the opening
	// prompt, which carries no conversation identifier, through its correlation.
	// Both indexes are partial: the empty string is the common case and indexing
	// it would cost more than it serves. No column is added and no row changes.
	if _, e = tx.Exec(ctx, `CREATE INDEX IF NOT EXISTS shadow_events_conversation ON shadow_events(organization_id,device_id,conversation_id,occurred_at) WHERE conversation_id<>'';
		CREATE INDEX IF NOT EXISTS shadow_events_correlation ON shadow_events(organization_id,device_id,correlation_id) WHERE correlation_id<>''`); e != nil {
		return nil, e
	}
	// Retire the per-event delivery ledger: nothing has ever read or written it,
	// and observability tracks its own deliveries in observability_deliveries.
	if _, e = tx.Exec(ctx, `DROP TABLE IF EXISTS shadow_deliveries`); e != nil {
		return nil, e
	}
	// Retire the Shadow AI export destinations (now Administration → Observability)
	// and, in Community, the sections this edition no longer offers. Without this,
	// a configuration stored before the change would be refused on the next save.
	//
	// Every statement below runs inside the per-organization loop. `shadow_settings`
	// and `shadow_device_overrides` are under FORCE row-level security and the
	// migration role owns them without BYPASSRLS, so the same statements written
	// outside the loop match **no rows at all** and report success — which is what
	// they did until 2026-09-10, silently, including the Community strip.
	// A bare SELECT is not a statement in plpgsql, and the fragment is inlined into a
	// loop body, so the Enterprise case needs a real no-op with its terminator.
	community := "PERFORM 1;"
	if Edition == "community" {
		community = `
		    UPDATE shadow_settings SET configuration=(CASE WHEN configuration ? 'model_access' THEN jsonb_set(configuration,'{model_access}','[]'::jsonb) ELSE configuration END) WHERE configuration->'model_access' <> '[]'::jsonb;
		    UPDATE shadow_settings SET configuration=jsonb_set(configuration,'{privacy,types}','[]'::jsonb) WHERE configuration ? 'privacy' AND configuration->'privacy'->'types' <> '[]'::jsonb;
		    UPDATE shadow_settings SET configuration=configuration - 'classification' WHERE configuration ? 'classification';
		    UPDATE shadow_device_overrides SET configuration=configuration - 'classification' - 'model_access' WHERE configuration ?| ARRAY['classification','model_access'];
		    UPDATE shadow_device_overrides SET configuration=jsonb_set(configuration,'{privacy,types}','[]'::jsonb) WHERE configuration ? 'privacy' AND configuration->'privacy'->'types' <> '[]'::jsonb;
`
	}
	if _, e = tx.Exec(ctx, `DO $mig$ DECLARE org uuid; BEGIN
		  FOR org IN SELECT id FROM organizations LOOP
		    PERFORM set_config('milvago.organization_id',org::text,true);
		    UPDATE shadow_settings SET configuration=jsonb_set(configuration,'{operations,destinations}','[]'::jsonb) WHERE configuration ? 'operations' AND configuration->'operations'->'destinations' <> '[]'::jsonb;
		    -- Metrics are no longer a policy setting (MILVAGO_SHADOW_METRICS governs them).
		    UPDATE shadow_settings SET configuration=jsonb_set(configuration,'{operations,metrics_enabled}','false'::jsonb) WHERE configuration ? 'operations' AND configuration->'operations'->'metrics_enabled' <> 'false'::jsonb;
		    `+community+`
		  END LOOP;
		  PERFORM set_config('milvago.organization_id','',true);
		END $mig$`); e != nil {
		return nil, e
	}
	// Signed updates are on by default in both editions, and the console only shows the
	// Operations section under MILVAGO_DEBUG: a policy written when the channel was
	// unavailable would otherwise stay off with no screen left to turn it back on.
	// Converge every stored policy once -- both editions, hence a version of its own --
	// so a deliberate opt-out made afterwards still survives the next start.
	// 20260912 did the same for Community alone, when its channel was opened.
	if _, e = tx.Exec(ctx, `DO $updates$ DECLARE org uuid; BEGIN
		  IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=20260917) THEN
		    FOR org IN SELECT id FROM organizations LOOP
		      PERFORM set_config('milvago.organization_id',org::text,true);
		      UPDATE shadow_settings SET revision=revision+1, configuration=configuration ||
		        jsonb_build_object('operations', COALESCE(configuration->'operations','{}'::jsonb) ||
		          jsonb_build_object('updates', COALESCE(configuration->'operations'->'updates','{}'::jsonb) || '{"enabled":true}'::jsonb))
		        WHERE organization_id=org AND COALESCE(configuration->'operations'->'updates'->'enabled','false'::jsonb) <> 'true'::jsonb;
		    END LOOP;
		    PERFORM set_config('milvago.organization_id','',true);
		    INSERT INTO schema_migrations(version) VALUES(20260917) ON CONFLICT DO NOTHING;
		  END IF;
		END $updates$`); e != nil {
		return nil, fmt.Errorf("automatic updates migration: %w", e)
	}
	role := pgx.Identifier{c.RuntimeRole}.Sanitize()
	if e = initializeObservability(ctx, tx, role); e != nil {
		return nil, e
	}
	if e = initializeModelAccess(ctx, tx, role); e != nil {
		return nil, e
	}
	if e = initializeAPIKeys(ctx, tx, role); e != nil {
		return nil, e
	}
	if e = initializeDetection(ctx, tx, role); e != nil {
		return nil, e
	}
	if e = initializeDeviceGroups(ctx, tx, role); e != nil {
		return nil, e
	}
	if e = initializePublisherClient(ctx, tx, role); e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, privacyMigration); e != nil {
		return nil, fmt.Errorf("privacy migration: %w", e)
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON privacy_settings,identity_reveals,subject_views,aggregate_reports,privacy_audit_outbox TO `+role); e != nil {
		return nil, e
	}
	// Repairs the built-in roles, and it has to run AFTER the seed loop above, never
	// before. That loop rewrites every built-in role from a SQL literal on every boot
	// (ON CONFLICT ... DO UPDATE SET permissions=EXCLUDED.permissions), and the literal
	// knows fewer permissions than builtinRolePermissions does. Moving this block
	// earlier, or gating it on schema_migrations so it runs once, would strip those
	// permissions again on the next restart -- a failure that only shows on the SECOND
	// boot. Each statement carries its own NOT (... = ANY(permissions)) guard, which is
	// what makes running it unconditionally on every boot correct.
	// TestBuiltinRolePermissionsConverge is the guard on all of this.
	if _, e = tx.Exec(ctx, `DO $$ DECLARE org uuid; BEGIN FOR org IN SELECT id FROM organizations LOOP PERFORM set_config('milvago.organization_id',org::text,true); INSERT INTO privacy_settings(organization_id) VALUES(org) ON CONFLICT DO NOTHING; UPDATE roles SET permissions=array_append(permissions,'reports.aggregate') WHERE name IN ('owner','admin','viewer') AND builtin AND NOT ('reports.aggregate'=ANY(permissions)); UPDATE roles SET permissions=permissions||ARRAY['identity.reveal','identity.erase'] WHERE name='owner' AND builtin AND NOT ('identity.reveal'=ANY(permissions)); UPDATE roles SET permissions=array_append(permissions,'content.purge') WHERE name='owner' AND builtin AND NOT ('content.purge'=ANY(permissions)); INSERT INTO roles(organization_id,name,permissions,builtin) VALUES(org,'reporter',ARRAY['overview.read','reports.aggregate'],true) ON CONFLICT DO NOTHING; END LOOP; PERFORM set_config('milvago.organization_id','',true); END $$`); e != nil {
		return nil, e
	}
	if e = initializeInstallers(ctx, tx, role); e != nil {
		return nil, e
	}
	// A deployment key is one durable credential per organization, not a package
	// valid for thirty days and a thousand installations. The constraints written
	// for the package model are dropped by definition rather than by name, since
	// PostgreSQL named them automatically.
	if _, e = tx.Exec(ctx, `ALTER TABLE installer_profiles ALTER COLUMN platform DROP NOT NULL;
		ALTER TABLE installer_profiles ADD COLUMN IF NOT EXISTS rotated_at timestamptz;
		ALTER TABLE installer_profiles ADD COLUMN IF NOT EXISTS revoked_at timestamptz;
		-- Two replicas starting together both saw no key and both minted one. The
		-- loser was a live credential no operator could see, because every read
		-- takes the newest row. The database decides instead.
		CREATE UNIQUE INDEX IF NOT EXISTS installer_profiles_one_active_key
		  ON installer_profiles(organization_id) WHERE platform IS NULL AND NOT revoked;
		DO $mig$ DECLARE c record; BEGIN
		  FOR c IN SELECT con.conname, pg_get_constraintdef(con.oid) AS def FROM pg_constraint con
		    JOIN pg_class cl ON cl.oid=con.conrelid WHERE cl.relname='installer_profiles' AND con.contype='c' LOOP
		    IF c.def LIKE '%expires_at%' OR c.def LIKE '%max_uses%' OR c.def LIKE '%platform%' THEN
		      EXECUTE format('ALTER TABLE installer_profiles DROP CONSTRAINT %I', c.conname);
		    END IF;
		  END LOOP;
		END $mig$;
		ALTER TABLE installer_profiles ADD CONSTRAINT installer_profiles_platform_check CHECK(platform IS NULL OR platform IN ('windows','linux'))`); e != nil {
		return nil, e
	}
	// An installation belongs to the organization and to the identity the agent
	// chose, not to the key that bought it. Keying it on the key would orphan every
	// device on the next rotation, and would block the purge of retired keys.
	if _, e = tx.Exec(ctx, `DO $mig$ BEGIN
		  IF EXISTS(SELECT 1 FROM pg_constraint WHERE conname='installer_installations_pkey'
		            AND array_length(conkey,1)=3) THEN
		    ALTER TABLE installer_installations DROP CONSTRAINT installer_installations_organization_id_profile_id_fkey;
		    ALTER TABLE installer_installations DROP CONSTRAINT installer_installations_pkey;
		    ALTER TABLE installer_installations ALTER COLUMN profile_id DROP NOT NULL;
		    ALTER TABLE installer_installations ADD PRIMARY KEY(organization_id,installation_id);
		  END IF;
		END $mig$`); e != nil {
		return nil, e
	}
	// The per-platform installation package is retired. Rows from that model still
	// carry a live secret_hash, so leaving them unrevoked would let a package
	// distributed before the durable key keep enrolling devices — and without the
	// platform and version checks that used to bound it. Idempotent.
	// The loop is not decoration: installer_profiles is under FORCE row-level
	// security, so an UPDATE without a tenant setting matches nothing at all and
	// reports success. Same shape as the settings/roles loop above.
	if _, e = tx.Exec(ctx, `DO $mig$ DECLARE org uuid; BEGIN
		  FOR org IN SELECT id FROM organizations LOOP
		    PERFORM set_config('milvago.organization_id',org::text,true);
		    UPDATE installer_profiles SET revoked=true,secret_ciphertext='' WHERE platform IS NOT NULL AND NOT revoked;
		    -- A ceiling of a million was no ceiling. Ten thousand is far above any
		    -- real fleet and is a hard stop for a key used to mint devices in bulk.
		    UPDATE installer_profiles SET max_uses=10000 WHERE platform IS NULL AND max_uses>10000;
		  END LOOP;
		  PERFORM set_config('milvago.organization_id','',true);
		END $mig$`); e != nil {
		return nil, e
	}
	// Make every per-tenant foreign key cascade from its parent so deleting an
	// organization purges its rows across all tables in one statement. Runs after
	// all tables (base, edition, shadow, observability, model-access, installers)
	// exist. Excludes the shared users table (never deleted with an org) and the
	// organizations.parent_id self-reference (deleting a parent with children must
	// fail, not silently remove the subtree). Idempotent: skips FKs already CASCADE.
	if _, e = tx.Exec(ctx, `DO $mig$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT con.conname, cl.relname AS tbl, rf.relname AS parent,
           (SELECT a.attname FROM pg_attribute a WHERE a.attrelid=con.conrelid AND a.attnum=con.conkey[1]) AS col
    FROM pg_constraint con
    JOIN pg_class cl ON cl.oid=con.conrelid
    JOIN pg_class rf ON rf.oid=con.confrelid
    JOIN pg_namespace ns ON ns.oid=cl.relnamespace
    WHERE con.contype='f' AND ns.nspname='public'
      AND rf.relname<>'users'
      AND NOT (cl.relname='organizations' AND rf.relname='organizations')
      AND array_length(con.conkey,1)=1
      AND con.confdeltype<>'c'
  LOOP
    EXECUTE format('ALTER TABLE public.%I DROP CONSTRAINT %I',r.tbl,r.conname);
    EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY (%I) REFERENCES public.%I ON DELETE CASCADE',r.tbl,r.conname,r.col,r.parent);
  END LOOP;
  -- Deleting one device permanently must take its own rows with it (events,
  -- overrides, observations, installations). Those foreign keys are composite
  -- (organization_id, device_id), so the single-column loop above skips them.
  FOR r IN
    SELECT con.conname, cl.relname AS tbl,
           (SELECT string_agg(quote_ident(a.attname),',' ORDER BY k.ord)
              FROM unnest(con.conkey) WITH ORDINALITY k(attnum,ord)
              JOIN pg_attribute a ON a.attrelid=con.conrelid AND a.attnum=k.attnum) AS cols,
           (SELECT string_agg(quote_ident(a.attname),',' ORDER BY k.ord)
              FROM unnest(con.confkey) WITH ORDINALITY k(attnum,ord)
              JOIN pg_attribute a ON a.attrelid=con.confrelid AND a.attnum=k.attnum) AS refcols
    FROM pg_constraint con
    JOIN pg_class cl ON cl.oid=con.conrelid
    JOIN pg_class rf ON rf.oid=con.confrelid
    JOIN pg_namespace ns ON ns.oid=cl.relnamespace
    WHERE con.contype='f' AND ns.nspname='public' AND rf.relname='devices'
      AND con.confdeltype<>'c'
  LOOP
    EXECUTE format('ALTER TABLE public.%I DROP CONSTRAINT %I',r.tbl,r.conname);
    EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY (%s) REFERENCES public.devices(%s) ON DELETE CASCADE',r.tbl,r.conname,r.cols,r.refcols);
  END LOOP;
END $mig$`); e != nil {
		return nil, fmt.Errorf("cascade migration: %w", e)
	}
	if _, e = tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON shadow_settings,shadow_device_overrides,collaborators,device_collaborators,shadow_events,shadow_content,shadow_saved_filters,device_association_requests TO `+role+`; GRANT USAGE ON SEQUENCE shadow_revision TO `+role+`; GRANT EXECUTE ON FUNCTION association_identity(bytea) TO `+role); e != nil {
		return nil, e
	}
	if grants := editionGrants(role); grants != "" {
		if _, e = tx.Exec(ctx, grants); e != nil {
			return nil, e
		}
	}
	// DELETE on audit exists for the hourly retention purge alone. Granting it
	// opens nothing by itself: the reject_audit_change trigger remains the only
	// authority — UPDATE is never allowed, and DELETE only under a
	// transaction-local flag with the 730-day floor engraved in the trigger.
	if _, e = tx.Exec(ctx, `REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT USAGE ON SCHEMA public TO `+role+`; GRANT SELECT,INSERT,UPDATE,DELETE ON users,sessions,login_attempts,setup_sessions,memberships,roles,settings,policies,enrollments,devices,events,ldap_directories TO `+role+`; GRANT SELECT,INSERT,UPDATE,DELETE ON organizations TO `+role+`; GRANT SELECT,UPDATE ON app_config TO `+role+`; GRANT SELECT,INSERT,DELETE ON audit TO `+role+`; GRANT EXECUTE ON FUNCTION enrollment_identity(bytea),device_identity(bytea),user_organizations(uuid),effective_access(uuid,uuid),subtree_members(uuid,uuid) TO `+role); e != nil {
		return nil, e
	}
	if e = initializeSharedRates(ctx, tx, role); e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS runtime_maintenance (task text PRIMARY KEY CHECK(task IN ('minute','hour')), completed_bucket timestamptz NOT NULL); GRANT SELECT,INSERT,UPDATE ON runtime_maintenance TO `+role+`; GRANT SELECT ON schema_migrations TO `+role); e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1) ON CONFLICT DO NOTHING`, runtimeSchemaVersion); e != nil {
		return nil, e
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return OpenRuntimeDatabase(ctx, c)
}

// OpenRuntimeDatabase validates the runtime boundary and schema without DDL or
// migration credentials. Only the deployment migration Job may change schema.
func OpenRuntimeDatabase(ctx context.Context, c Config) (*pgxpool.Pool, error) {
	p, e := pgxpool.New(ctx, c.DatabaseURL)
	if e != nil {
		return nil, e
	}
	var unsafe bool
	e = p.QueryRow(ctx, `SELECT r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR pg_has_role(current_user,'milvago_lookup','MEMBER') OR has_schema_privilege(current_user,'public','CREATE') OR EXISTS(SELECT 1 FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND pg_has_role(current_user,c.relowner,'MEMBER')) FROM pg_roles r WHERE r.rolname=current_user`).Scan(&unsafe)
	if e != nil || unsafe {
		p.Close()
		return nil, errors.New("runtime database role must be nonowner, non-superuser, NOBYPASSRLS and unable to create public schema objects")
	}
	var compatible bool
	if e = p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, runtimeSchemaVersion).Scan(&compatible); e != nil || !compatible {
		p.Close()
		return nil, errors.New("database schema is not initialized for this runtime; run MILVAGO_ROLE=migrate first")
	}
	if Edition == "community" {
		var count int
		if e = p.QueryRow(ctx, `SELECT count(*) FROM organizations`).Scan(&count); e != nil || count != 1 {
			p.Close()
			return nil, errors.New("Community requires exactly one organization")
		}
	}
	return p, nil
}

func tenantTx(ctx context.Context, p *pgxpool.Pool, org string) (pgx.Tx, error) {
	tx, e := p.Begin(ctx)
	if e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,true)`, org); e != nil {
		tx.Rollback(ctx)
		return nil, e
	}
	return tx, nil
}
func audit(ctx context.Context, tx pgx.Tx, org, actor, action, target string) error {
	// The acting API key, when there is one, is read from the transaction-local
	// setting the API key wrapper installed. Attribution is therefore a property
	// of the transaction rather than of the call: every existing caller keeps its
	// four arguments and gains it for free, and a handler written later cannot
	// forget it. `actor` stays the human -- accountability is never transferred to
	// a machine; api_key_id, or oauth_client for an MCP access token, says by what
	// means they acted.
	_, e := tx.Exec(ctx, `INSERT INTO audit(organization_id,actor,action,target,api_key_id,oauth_client) VALUES($1,$2,$3,$4,nullif(current_setting('milvago.api_key_id',true),'')::uuid,nullif(current_setting('milvago.oauth_client',true),''))`, org, actor, action, target)
	return e
}

// auditMany writes one line per target. Reading a conversation decrypts several
// texts in one request, and each of them is a content read: collapsing them into
// a single line would make a thread cheaper to account for than the same
// messages opened one by one. Attribution is read from the transaction-local
// setting exactly as in audit, so a key acting through this path is named too.
func auditMany(ctx context.Context, tx pgx.Tx, org, actor, action string, targets []string) error {
	if len(targets) == 0 {
		return nil
	}
	_, e := tx.Exec(ctx, `INSERT INTO audit(organization_id,actor,action,target,api_key_id,oauth_client) SELECT $1,$2,$3,t,nullif(current_setting('milvago.api_key_id',true),'')::uuid,nullif(current_setting('milvago.oauth_client',true),'') FROM unnest($4::text[]) AS t`, org, actor, action, targets)
	return e
}

func (a *App) Maintain(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	minuteTicker := time.NewTicker(time.Minute)
	defer minuteTicker.Stop()
	var metricsDone <-chan struct{}
	if Edition == "commercial" {
		done := make(chan struct{})
		metricsDone = done
		go func() {
			defer close(done)
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			a.refreshExportMetrics(ctx)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					a.refreshExportMetrics(ctx)
				}
			}
		}()
	}
	defer func() {
		if metricsDone != nil {
			<-metricsDone
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-minuteTicker.C:
			if e := a.maintenanceOnce(ctx, "minute", a.maintainMinute); e != nil && ctx.Err() == nil {
				a.log.Error("minute maintenance failed", "error", e)
			}
		case <-ticker.C:
			if e := a.maintenanceOnce(ctx, "hour", a.maintainHour); e != nil && ctx.Err() == nil {
				a.log.Error("hourly maintenance failed", "error", e)
			}
		}
	}
}

func (a *App) refreshExportMetrics(ctx context.Context) {
	defer func() { a.contain(recover(), "export metrics") }()
	refresh, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	if e := a.RefreshExportMetrics(refresh); e != nil && ctx.Err() == nil {
		a.log.Error("export pressure refresh failed", "error", e)
	}
}

// A transactional advisory lock prevents simultaneous old/new maintenance pods,
// and the completed bucket prevents a rolling replacement repeating the same
// period. Failed or interrupted work is retried; maintenance remains idempotent.
func (a *App) maintenanceOnce(ctx context.Context, task string, work func(context.Context) error) (e error) {
	// Registered first, so it runs after the transaction's rollback.
	defer func() {
		if a.contain(recover(), "maintenance "+task) {
			e = errors.New("maintenance task panicked")
		}
	}()
	if task != "minute" && task != "hour" {
		return errors.New("invalid maintenance task")
	}
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var held bool
	if e = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(726403211)`).Scan(&held); e != nil || !held {
		return e
	}
	var bucket time.Time
	var complete bool
	if e = tx.QueryRow(ctx, `SELECT date_trunc($1,clock_timestamp()), EXISTS(SELECT 1 FROM runtime_maintenance WHERE task=$1 AND completed_bucket>=date_trunc($1,clock_timestamp()))`, task).Scan(&bucket, &complete); e != nil || complete {
		return e
	}
	if e = work(ctx); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO runtime_maintenance(task,completed_bucket) VALUES($1,$2) ON CONFLICT(task) DO UPDATE SET completed_bucket=EXCLUDED.completed_bucket`, task, bucket); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (a *App) maintainMinute(ctx context.Context) error {
	if e := a.cleanupSharedRates(ctx); e != nil {
		return e
	}
	a.maintainPublisher(ctx)
	return ctx.Err()
}

func (a *App) maintainHour(ctx context.Context) error {
	if _, e := a.db.Exec(ctx, `DELETE FROM sessions WHERE expires_at<now(); DELETE FROM login_attempts WHERE expires_at<now(); DELETE FROM setup_sessions WHERE expires_at<now()`); e != nil {
		return e
	}
	a.revokeWithdrawnIdentities(ctx)
	rows, e := a.db.Query(ctx, `SELECT id FROM organizations`)
	if e != nil {
		return e
	}
	orgs := []string{}
	for rows.Next() {
		var org string
		if e = rows.Scan(&org); e != nil {
			break
		}
		orgs = append(orgs, org)
	}
	rows.Close()
	if e != nil {
		return e
	}
	if e = rows.Err(); e != nil {
		return e
	}
	var failures []error
	for _, org := range orgs {
		if e := a.purgeOrgRetention(ctx, org); e != nil {
			failures = append(failures, e)
		}
	}
	return errors.Join(failures...)
}

// purgeOrgRetention applies one organization's retention in a single
// transaction: expired encrypted prompt contents, events past their configured
// retention, stale enrollments, long-retired deployment keys and API keys, then
// the audit trail itself. It runs through the runtime pool — that is what the
// DELETE grant on audit exists for — while the append-only trigger stays the
// only authority on what may actually leave the audit table.
func (a *App) purgeOrgRetention(ctx context.Context, org string) error {
	tx, e := tenantTx(ctx, a.db, org)
	if e != nil {
		return e
	}
	e = a.maintainPrivacy(ctx, tx, org, time.Now().UTC())
	if e == nil {
		_, e = tx.Exec(ctx, `DELETE FROM shadow_content WHERE expires_at<now(); DELETE FROM device_collaborators WHERE expires_at<now()`)
	}
	if e == nil {
		_, e = tx.Exec(ctx, `DELETE FROM shadow_events WHERE occurred_at<now()-make_interval(days => (SELECT retention_days FROM settings WHERE organization_id=$1))`, org)
	}
	if e == nil {
		_, e = tx.Exec(ctx, `DELETE FROM enrollments WHERE expires_at<now()-interval '1 day'`)
	}
	// Retired deployment keys are kept a month so the audit trail still
	// resolves against a recently rotated one, then dropped. Installations
	// keep the identifier as a sealing purpose, not as a reference.
	if e == nil {
		_, e = tx.Exec(ctx, `DELETE FROM installer_profiles WHERE revoked AND coalesce(revoked_at,created_at)<now()-interval '30 days'`)
	}
	// An API key that is revoked or expired can never authenticate again
	// (filtered by the identity lookup and again under the row lock), so
	// keeping the row is purely so the audit trail still resolves the key's
	// name. Ninety days puts that comfortably beyond an incident review.
	if e == nil {
		_, e = tx.Exec(ctx, `DELETE FROM api_keys WHERE COALESCE(revoked_at,expires_at)<now()-interval '90 days'`)
	}
	// The audit trail keeps its own retention, deliberately longer than the
	// event retention and deliberately not configurable: an administrator
	// must not be able to shorten the record of their own actions. The
	// append-only trigger enforces the same floor independently.
	if e == nil {
		_, e = tx.Exec(ctx, `SELECT set_config('milvago.purge_audit_before',(now()-interval '730 days')::text,true); DELETE FROM audit WHERE occurred_at<now()-interval '730 days'`)
	}
	if e == nil {
		e = tx.Commit(ctx)
	} else {
		tx.Rollback(ctx)
	}
	return e
}
