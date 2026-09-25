package app

import (
	"archive/zip"
	"bytes"
	"testing"
)

// xpiFuzzFixture builds a minimal ZIP archive with a single manifest.json entry (or
// none, when manifest is empty), for use as fuzz seed corpus. It never fails on the
// static strings this file passes it, so any error is programmer error, not fuzz input.
func xpiFuzzFixture(manifest string) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	if manifest != "" {
		entry, err := w.Create("manifest.json")
		if err != nil {
			panic(err)
		}
		if _, err = entry.Write([]byte(manifest)); err != nil {
			panic(err)
		}
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// FuzzFirefoxXPIInfo exercises firefoxXPIInfo (ext.go), the ZIP + manifest.json parser
// behind Firefox self-distribution. The bytes it reads come from a signed package baked
// into the image, not the network directly, but it is a byte-oriented archive parser
// with no other input gate ahead of it -- named explicitly in this fuzzing brief for
// ext.go, and the same class of parser that has caused panics via crafted ZIP central
// directories in other codebases.
//
// Invariant: on acceptance, the returned version and gecko id always match the patterns
// the caller (extFirefoxUpdate) trusts without re-checking.
func FuzzFirefoxXPIInfo(f *testing.F) {
	f.Add(xpiFuzzFixture(`{"version":"0.5.10","browser_specific_settings":{"gecko":{"id":"browser@milvago.app"}}}`))
	f.Add([]byte("not a zip"))
	f.Add(xpiFuzzFixture(`{`))
	f.Add(xpiFuzzFixture(``))
	f.Add([]byte{})
	f.Add(xpiFuzzFixture(`{"version":"0.5.10","browser_specific_settings":{"gecko":{"id":"browser@milvago.app"}}} {}`))

	f.Fuzz(func(t *testing.T, payload []byte) {
		version, id, err := firefoxXPIInfo(payload)
		if err != nil {
			if version != "" || id != "" {
				t.Fatalf("error case returned non-empty results: %q %q", version, id)
			}
			return
		}
		if !extVersionPattern.MatchString(version) {
			t.Fatalf("accepted invalid version: %q", version)
		}
		if !geckoIDPattern.MatchString(id) {
			t.Fatalf("accepted invalid gecko id: %q", id)
		}
	})
}
