//go:build !commercial

package app

import (
	"context"
	"testing"
)

func regexTestOrganization(t *testing.T, f *observabilityFixture) string {
	t.Helper()
	var id string
	if err := f.admin.QueryRow(context.Background(), `INSERT INTO organizations(name) VALUES('Other synthetic regex tenant') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
