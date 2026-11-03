package app

import (
	"context"
	"encoding/json"
	"testing"
)

func TestCandidateDiscoveryStateWithNoCandidates(t *testing.T) {
	p := newProjectionFixture(t)
	ctx := context.Background()
	if _, err := p.admin.Exec(ctx, `INSERT INTO privacy_settings(organization_id) VALUES($1) ON CONFLICT DO NOTHING`, p.org); err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{false, true} {
		raw, err := json.Marshal(map[string]bool{"discovery_enabled": enabled})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = p.admin.Exec(ctx, `UPDATE privacy_settings SET configuration=configuration||$2::jsonb WHERE organization_id=$1`, p.org, string(raw)); err != nil {
			t.Fatal(err)
		}
		w := p.as("owner", "GET", "/api/detection/candidates", nil)
		requireHTTP(t, w, 200)
		var body struct {
			Enabled *bool             `json:"discovery_enabled"`
			Items   []json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Enabled == nil || *body.Enabled != enabled || len(body.Items) != 0 {
			t.Fatalf("discovery state must be explicit and independent of candidates: %s", w.Body.String())
		}
	}
}
