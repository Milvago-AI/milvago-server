package app

import (
	"context"
	"testing"
)

// Custom/legacy behavior tests intentionally omit the optional predefined objects.
func newDLPFixtureWithoutDefaultRules(t *testing.T) *observabilityFixture {
	f := newObservabilityFixture(t)
	if _, err := f.admin.Exec(context.Background(), `UPDATE dlp_settings SET policy=jsonb_set(policy,'{rules}','[]'::jsonb),default_rule_ids='[]'::jsonb WHERE organization_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	return f
}
