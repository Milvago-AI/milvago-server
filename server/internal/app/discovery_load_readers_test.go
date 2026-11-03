package app

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func discoveryLoadReaders(t *testing.T, f *observabilityFixture, count int) []*observabilityFixture {
	t.Helper()
	if count < 1 || count > 100 {
		t.Fatal("interactive fixture must stay within 100 people")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	people := make([]*observabilityFixture, 0, count)
	for index := 0; index < count; index++ {
		person := &observabilityFixture{a: f.a, admin: f.admin, org: f.org, csrf: randomToken()}
		if err := f.admin.QueryRow(ctx, `INSERT INTO users(subject,email,display_name) VALUES($1,$2,'Synthetic load operator') RETURNING id`, fmt.Sprintf("discovery-load-%03d", index), fmt.Sprintf("discovery-load-%03d@example.test", index)).Scan(&person.user); err != nil {
			t.Fatal(err)
		}
		if _, err := f.admin.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, f.org, person.user); err != nil {
			t.Fatal(err)
		}
		token := randomToken()
		person.owner = &http.Cookie{Name: cookieName("session"), Value: token}
		if _, err := f.admin.Exec(ctx, `INSERT INTO sessions(token_hash,user_id,organization_id,csrf_token,encrypted_tokens,mfa,expires_at,identity_expires_at)
 VALUES($1,$2,$3,$4,$5,true,$6,$6)`, hash(token), person.user, f.org, person.csrf, []byte("synthetic-session"), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		people = append(people, person)
	}
	return people
}

func verifyDiscoveryLoadReaderAdmission(t *testing.T, f *observabilityFixture, people []*observabilityFixture) {
	t.Helper()
	keys := make([][]byte, 0, len(people))
	for _, person := range people {
		keys = append(keys, hash("person "+person.user))
	}
	var admitted int
	if err := f.admin.QueryRow(context.Background(), `SELECT count(DISTINCT key_hash) FROM rate_counters WHERE family=1 AND key_hash=ANY($1::bytea[])`, keys).Scan(&admitted); err != nil {
		t.Fatal(err)
	}
	if admitted != len(people) {
		t.Fatalf("interactive fixture used %d person budgets, want %d", admitted, len(people))
	}
	t.Logf("interactive people verified through real admission counters: %d", admitted)
}

func TestDiscoveryLoadReadersUseDistinctPeopleAndRealAdmission(t *testing.T) {
	f := newObservabilityFixture(t)
	people := discoveryLoadReaders(t, f, 100)
	users, tokens := map[string]bool{}, map[string]bool{}
	for _, person := range people {
		if person.org != f.org || person.user == f.user || users[person.user] || tokens[person.owner.Value] {
			t.Fatal("interactive actors share an identity or credential")
		}
		users[person.user], tokens[person.owner.Value] = true, true
		requireHTTP(t, person.call("GET", "/api/discovery/applications?limit=1", nil, ""), 200)
	}
	verifyDiscoveryLoadReaderAdmission(t, f, people)
}
