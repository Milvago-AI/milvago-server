//go:build !commercial

package app

import "testing"

// Community has one organization and one realm: nothing to provision or route.
func (f *identityScenarioFixture) testEnterpriseRealms(*testing.T) {}
