package app

import (
	"encoding/json"
	"testing"
)

// The decoded catalogue is memoized, and every hit is handed out through
// cloneDetection: a deep copy whose slices and pointers share nothing with the cached
// value. Before that clone the copies shared backing arrays, and a caller writing
// through one poisoned every later request in the process. This test writes through a
// served copy and reads the memo back; it is what keeps the clone from quietly
// lapsing into a shallow one.
func TestDecodedDetectionIsNotMutableThroughItsCopies(t *testing.T) {
	first, e := decodedDetection(detectionFactory)
	if e != nil {
		t.Fatal(e)
	}
	if len(first.Providers) == 0 {
		t.Fatal("the factory catalogue carries no provider: this test would prove nothing")
	}
	original := first.Providers[0].Label
	// Whether the first call was a miss or a hit depends on what ran before in this
	// process. The second is always a hit, and the hit path -- cloneDetection(cached) --
	// is the one every production request after the first takes, so both copies are
	// written through and the memo is read back after each.
	poisonDetection(t, first)
	hit := pristineDetection(t, original, "a write through the first copy")
	poisonDetection(t, hit)
	pristineDetection(t, original, "a write through a copy served from the memo")
}

// poisonDetection writes through every kind of field the document carries, not just
// the first one that came to mind: a string, a slice of strings, a nested slice inside
// Network, and -- the one the first version of this test missed -- the *int a Network
// rule can carry. A slice clone copies that struct by value, so the pointer was shared
// with the memo until 2026-09-21.
func poisonDetection(t *testing.T, c DetectionContent) {
	t.Helper()
	c.Providers[0].Label = "written through a copy"
	if len(c.Providers[0].Domains) > 0 {
		c.Providers[0].Domains[0] = "written.example.invalid"
	}
	segments := 0
	for i := range c.Providers {
		for j := range c.Providers[i].Network {
			if p := c.Providers[i].Network[j].ConversationURLSegment; p != nil {
				*p = 9999
				segments++
			}
		}
	}
	if segments == 0 {
		t.Fatal("no rule in the factory catalogue carries conversation_url_segment: the pointer case would prove nothing")
	}
}

// pristineDetection reads the memo back and fails if any of poisonDetection's writes
// reached it.
func pristineDetection(t *testing.T, original, after string) DetectionContent {
	t.Helper()
	c, e := decodedDetection(detectionFactory)
	if e != nil {
		t.Fatal(e)
	}
	if c.Providers[0].Label != original {
		t.Fatalf("%s reached the memo: %q became %q", after, original, c.Providers[0].Label)
	}
	if len(c.Providers[0].Domains) > 0 && c.Providers[0].Domains[0] == "written.example.invalid" {
		t.Fatalf("%s reached the memo through a cloned slice", after)
	}
	for i := range c.Providers {
		for j := range c.Providers[i].Network {
			if p := c.Providers[i].Network[j].ConversationURLSegment; p != nil && *p == 9999 {
				t.Fatalf("%s reached the memo through the *int of provider %d rule %d", after, i, j)
			}
		}
	}
	return c
}

// Keyed on the bytes, never on the revision. A revision is a sequence in one database
// and this process serves several -- the harness drops the schema between cases, so
// revision 1 names a different document each time. Alternating two documents proves
// the key is the content.
func TestDecodedDetectionKeysOnContentNotOnOrder(t *testing.T) {
	var altered DetectionContent
	if e := json.Unmarshal(detectionFactory, &altered); e != nil {
		t.Fatal(e)
	}
	altered.Providers[0].Label = "Second document"
	second, e := json.Marshal(altered)
	if e != nil {
		t.Fatal(e)
	}
	for _, step := range []struct {
		raw  []byte
		want string
	}{
		{detectionFactory, ""},
		{second, "Second document"},
		{detectionFactory, ""},
		{second, "Second document"},
	} {
		c, e := decodedDetection(step.raw)
		if e != nil {
			t.Fatal(e)
		}
		if step.want != "" && c.Providers[0].Label != step.want {
			t.Fatalf("the memo answered %q for a document labelled %q", c.Providers[0].Label, step.want)
		}
		if step.want == "" && c.Providers[0].Label == "Second document" {
			t.Fatal("the memo answered the other document")
		}
	}
}
