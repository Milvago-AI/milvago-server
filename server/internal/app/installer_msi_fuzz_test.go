package app

import (
	"bytes"
	"testing"
)

// FuzzReadCFB exercises readCFB (installer_msi.go), the compound-file (OLE/CFB, MSI
// container) parser used to read the WiX release template before its provisioning
// stream is replaced and the file rewritten. The bytes it parses come from a release
// artifact on disk today, not the network, but it is a byte-oriented binary-format
// decoder with no other gate ahead of it -- named explicitly in this fuzzing brief for
// installer_msi.go, and structurally the same class of parser (sector chains, a FAT,
// a mini-FAT, DIFAT) that regularly hides out-of-bounds reads in the wild.
//
// Invariant: on acceptance, every directory entry is exactly the fixed 128-byte record
// size setMSIBinaryStream and cfbFile.bytes() assume, and no stream is reported longer
// than the bytes actually supplied.
func FuzzReadCFB(f *testing.F) {
	valid := &cfbFile{major: 3, shift: 9, entries: [][]byte{
		cfbTestEntry("Root Entry", 5, cfbFree, cfbFree, 1),
		cfbTestEntry(msiStreamName("Binary.MilvagoProvision"), 2, cfbFree, cfbFree, cfbFree),
	}, streams: map[int][]byte{1: []byte("{}")}}
	rawValid, err := valid.bytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(rawValid)
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0}, 512))
	f.Add(append([]byte{}, cfbSignature...))
	f.Add(bytes.Repeat([]byte{0xff}, 4096))
	f.Add(bytes.Repeat([]byte("release payload "), 8<<20/16)) // large, non-CFB

	f.Fuzz(func(t *testing.T, raw []byte) {
		parsed, err := readCFB(raw)
		if err != nil {
			if parsed != nil {
				t.Fatalf("error case returned a non-nil file")
			}
			return
		}
		for i, e := range parsed.entries {
			if len(e) != cfbEntrySize {
				t.Fatalf("entry %d has size %d, want %d", i, len(e), cfbEntrySize)
			}
		}
		for i, s := range parsed.streams {
			if len(s) > len(raw) {
				t.Fatalf("stream %d is %d bytes, larger than the %d-byte input", i, len(s), len(raw))
			}
		}
	})
}
