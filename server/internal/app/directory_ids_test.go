package app

import "testing"

// Keycloak 26 names components with base64url identifiers, which may start with "_" or
// "-": a directory saved with one must not be refused as unidentified.
func TestKeycloakIdentifierPattern(t *testing.T) {
	for _, id := range []string{"_VZ7pQdzTveprw8YOUruSA", "-Kq1x9", "3f1c2b7e-8f6a-4c1d-9e2b-0a1b2c3d4e5f", "f:component:id"} {
		if !ldapSubjectPattern.MatchString(id) {
			t.Fatal("identifier refused", id)
		}
	}
	for _, id := range []string{"", ".", "../x", "a/b", "a b", ".hidden"} {
		if ldapSubjectPattern.MatchString(id) {
			t.Fatal("unsafe identifier accepted", id)
		}
	}
}
