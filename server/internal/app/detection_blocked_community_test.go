//go:build !commercial

package app

import "testing"

// Community blocks no known platform: the route does not exist, and a device policy
// never carries a list.
func TestCommunityCannotBlockPlatforms(t *testing.T) {
	g := newDeviceGroupsFixture(t)
	if code := g.owner("PUT", "/api/detection/platforms/mammouth/blocked", map[string]bool{"blocked": true}).Code; code != 404 && code != 405 {
		t.Fatalf("Community served the block route: %d", code)
	}
	_, config := g.signedPolicy(t)
	if _, ok := config["blocked_platforms"]; ok {
		t.Fatal("a Community policy carries blocked platforms")
	}
}
