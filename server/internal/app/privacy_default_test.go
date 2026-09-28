package app

import "testing"

func TestDefaultPrivacyEnablesCandidateDiscovery(t *testing.T) {
	if !defaultPrivacy().DiscoveryEnabled {
		t.Fatal("candidate discovery default is disabled")
	}
}
