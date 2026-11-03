//go:build !commercial

package app

// Additional inventory sources are edition-specific. Community reads its own
// discovery observations without importing another edition's collectors.
func discoveryInventoryVisible(*Session) bool             { return false }
func discoveryInventorySource(*Session) string            { return "discovery_identifications" }
func discoveryInventoryMetadata(string, []map[string]any) {}

// Optional inventory sources contribute bounded device-level aggregates rather
// than expanding their evidence through the discovery-object grouping pass.
func discoveryAdditionalInventoryDevices(*Session) string {
	return `SELECT NULL::text application_id,NULL::uuid device_id,0::bigint instances,
 NULL::timestamptz first_seen,NULL::timestamptz last_seen,false executed,false indication,false installed,false interface WHERE false`
}

func discoveryAdditionalInventoryKeys(bool) string {
	return `SELECT NULL::text application_id WHERE false`
}
