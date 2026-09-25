CREATE TABLE IF NOT EXISTS device_groups (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 organization_id uuid NOT NULL REFERENCES organizations,
 name text NOT NULL, description text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(organization_id,id), UNIQUE(organization_id,name)
);
CREATE TABLE IF NOT EXISTS shadow_group_overrides (
 organization_id uuid NOT NULL, group_id uuid NOT NULL,
 revision bigint NOT NULL DEFAULT nextval('shadow_revision'), configuration jsonb NOT NULL,
 PRIMARY KEY(organization_id,group_id),
 FOREIGN KEY(organization_id,group_id) REFERENCES device_groups(organization_id,id) ON DELETE CASCADE
);
-- One group per device. group_revision is drawn from shadow_revision on every
-- assignment change so the effective policy revision of the device only grows
-- (see effectiveShadow); it is not a foreign key and never decreases.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS group_id uuid;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS group_revision bigint NOT NULL DEFAULT 0;
-- NO ACTION rather than SET NULL: a composite SET NULL would also blank
-- organization_id. Deleting a group detaches its devices explicitly first
-- (deleteDeviceGroup); deleting an organization cascades to both tables in one
-- statement, which NO ACTION accepts.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='devices_group_fkey') THEN
  ALTER TABLE devices ADD CONSTRAINT devices_group_fkey FOREIGN KEY(organization_id,group_id) REFERENCES device_groups(organization_id,id);
 END IF;
END $$;
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['device_groups','shadow_group_overrides'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename=t AND policyname='tenant') THEN
   EXECUTE format('CREATE POLICY tenant ON %I USING (organization_id=nullif(current_setting(''milvago.organization_id'',true),'''')::uuid) WITH CHECK (organization_id=nullif(current_setting(''milvago.organization_id'',true),'''')::uuid)',t);
  END IF;
 END LOOP;
END $$;
