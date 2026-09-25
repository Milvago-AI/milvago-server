package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func encodeKey(fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func TestContentKeysParsing(t *testing.T) {
	session := bytes.Repeat([]byte{9}, 32)

	t.Run("a single version is its own active version", func(t *testing.T) {
		t.Setenv("CONTENT_KEYS", "1:"+encodeKey(1))
		keys, active, e := decodeContentKeys(session)
		if e != nil || active != 1 || len(keys) != 1 {
			t.Fatalf("keys=%d active=%d error=%v", len(keys), active, e)
		}
	})

	t.Run("the highest version present is the active one", func(t *testing.T) {
		// Written out of order on purpose: the active version is a property of the
		// list, not of where an operator happened to append.
		t.Setenv("CONTENT_KEYS", "3:"+encodeKey(3)+", 1:"+encodeKey(1)+" , 2:"+encodeKey(2))
		keys, active, e := decodeContentKeys(session)
		if e != nil || active != 3 || len(keys) != 3 {
			t.Fatalf("keys=%d active=%d error=%v", len(keys), active, e)
		}
	})

	for name, value := range map[string]string{
		"absent":              "",
		"blank":               "   ",
		"no version":          encodeKey(1),
		"version zero":        "0:" + encodeKey(1),
		"negative version":    "-1:" + encodeKey(1),
		"non-numeric version": "one:" + encodeKey(1),
		"duplicate version":   "1:" + encodeKey(1) + ",1:" + encodeKey(2),
		"short key":           "1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)),
		"not base64":          "1:!!!!",
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			t.Setenv("CONTENT_KEYS", value)
			if _, _, e := decodeContentKeys(session); e == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}

	// The separation is the whole point of the variable: an operator who pastes the
	// session key here rebuilds the single-root design by hand, and nothing would
	// complain until the day SESSION_KEY is rotated and every sealed value becomes
	// unreadable. Refused at startup instead.
	t.Run("refuses a content key equal to the session key", func(t *testing.T) {
		t.Setenv("CONTENT_KEYS", "1:"+base64.StdEncoding.EncodeToString(session))
		_, _, e := decodeContentKeys(session)
		if e == nil || !strings.Contains(e.Error(), "differ from SESSION_KEY") {
			t.Fatalf("error was %v", e)
		}
	})

	// Including when it is a later version, which is the shape a careless rotation
	// takes: append a key, copy the wrong value.
	t.Run("refuses it on any version, not only the first", func(t *testing.T) {
		t.Setenv("CONTENT_KEYS", "1:"+encodeKey(1)+",2:"+base64.StdEncoding.EncodeToString(session))
		if _, _, e := decodeContentKeys(session); e == nil {
			t.Fatal("a later version equal to the session key was accepted")
		}
	})
}

func TestContentEnvelopeVersioning(t *testing.T) {
	one, two := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	// A signing key is set to prove it is no longer a fallback root: the previous
	// implementation sealed with its seed when no content key was configured.
	before := &App{config: Config{ContentKeys: map[int][]byte{1: one}, ContentVersion: 1, SigningKey: ed25519.NewKeyFromSeed(make([]byte, 32))}}
	sealed, e := before.sealShadow("org-one", "event:one", []byte("synthetic sensitive text"))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(sealed, "v1.") {
		t.Fatalf("the envelope must name its key version: %q", sealed[:min(len(sealed), 8)])
	}

	t.Run("the sealing version opens it", func(t *testing.T) {
		plain, e := before.openShadow("org-one", "event:one", sealed)
		if e != nil || string(plain) != "synthetic sensitive text" {
			t.Fatalf("plain=%q error=%v", plain, e)
		}
	})

	// Rotation: append a higher version. Everything already sealed keeps opening,
	// and new values move onto the new key by themselves.
	after := &App{config: Config{ContentKeys: map[int][]byte{1: one, 2: two}, ContentVersion: 2}}
	t.Run("rotation keeps the old ciphertext readable", func(t *testing.T) {
		plain, e := after.openShadow("org-one", "event:one", sealed)
		if e != nil || string(plain) != "synthetic sensitive text" {
			t.Fatalf("plain=%q error=%v", plain, e)
		}
	})
	t.Run("and seals new values with the active version", func(t *testing.T) {
		rotated, e := after.sealShadow("org-one", "event:one", []byte("after rotation"))
		if e != nil || !strings.HasPrefix(rotated, "v2.") {
			t.Fatalf("sealed=%q error=%v", rotated, e)
		}
		if _, e := before.openShadow("org-one", "event:one", rotated); e == nil {
			t.Fatal("a value sealed with the new key opened without it")
		}
	})

	// Decommissioning the old key is what finishes a rotation, and it must be the
	// thing that makes un-re-sealed data fail loudly rather than silently.
	t.Run("retiring a version makes its ciphertext unreadable", func(t *testing.T) {
		only := &App{config: Config{ContentKeys: map[int][]byte{2: two}, ContentVersion: 2}}
		if _, e := only.openShadow("org-one", "event:one", sealed); e == nil {
			t.Fatal("a retired version still opened its ciphertext")
		}
	})

	t.Run("the version label is bound to the ciphertext", func(t *testing.T) {
		// Relabelling must not be a way to ask for a different key over the same
		// bytes: the version travels outside the ciphertext, so it is in the
		// additional data.
		relabelled := "v2." + strings.TrimPrefix(sealed, "v1.")
		if _, e := after.openShadow("org-one", "event:one", relabelled); e == nil {
			t.Fatal("a relabelled envelope was accepted")
		}
	})

	t.Run("an unversioned envelope is refused", func(t *testing.T) {
		// The format written before versioning existed. There is no compatibility
		// path on purpose: reading it would require guessing which root sealed it.
		legacy := strings.TrimPrefix(sealed, "v1.")
		_, e := after.openShadow("org-one", "event:one", legacy)
		if e == nil || !strings.Contains(e.Error(), "unversioned") {
			t.Fatalf("error was %v", e)
		}
	})

	t.Run("a missing key version is an error, never a substitution", func(t *testing.T) {
		orphan := &App{config: Config{ContentKeys: map[int][]byte{1: one}, ContentVersion: 1, SigningKey: ed25519.NewKeyFromSeed(make([]byte, 32))}}
		if _, e := orphan.openShadow("org-one", "event:one", "v7.AAAA"); e == nil {
			t.Fatal("an unconfigured version was accepted")
		}
	})

	t.Run("organization and purpose still separate ciphertexts", func(t *testing.T) {
		for _, c := range [][2]string{{"org-two", "event:one"}, {"org-one", "event:two"}} {
			if _, e := before.openShadow(c[0], c[1], sealed); e == nil {
				t.Fatalf("ciphertext accepted for %s/%s", c[0], c[1])
			}
		}
	})
}
