CREATE TABLE model_enforcement (
 organization_id uuid NOT NULL, device_id uuid NOT NULL,
 platform_id text NOT NULL, channel text NOT NULL CHECK(channel IN ('browser','native')),
 revision bigint NOT NULL CHECK(revision>0),
 status text NOT NULL CHECK(status IN ('applied','unavailable')),
 reason text NOT NULL DEFAULT '', mechanism text NOT NULL,
 reported_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,device_id,platform_id,channel),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id) ON DELETE CASCADE,
 CHECK((channel='browser' AND mechanism='browser-request') OR (channel='native' AND mechanism='local-proxy'))
);
ALTER TABLE model_enforcement ENABLE ROW LEVEL SECURITY;
ALTER TABLE model_enforcement FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON model_enforcement USING(current_user <> 'milvago_lookup' AND organization_id=nullif(current_setting('milvago.organization_id',true),'')::uuid) WITH CHECK(current_user <> 'milvago_lookup' AND organization_id=nullif(current_setting('milvago.organization_id',true),'')::uuid);
ALTER TABLE shadow_events ADD COLUMN platform_id text NOT NULL DEFAULT '';
ALTER TABLE shadow_events ADD COLUMN decision_reason text NOT NULL DEFAULT '' CHECK(decision_reason IN ('','model_denied','model_unknown','control_unavailable'));
