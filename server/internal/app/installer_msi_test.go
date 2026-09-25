package app

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
)

func cfbTestEntry(name string, kind byte, left, right, child uint32) []byte {
	e := make([]byte, cfbEntrySize)
	units := utf16.Encode([]rune(name))
	for i, u := range units {
		binary.LittleEndian.PutUint16(e[2*i:], u)
	}
	binary.LittleEndian.PutUint16(e[64:], uint16(2*len(units)+2))
	e[66], e[67] = kind, 1
	binary.LittleEndian.PutUint32(e[68:], left)
	binary.LittleEndian.PutUint32(e[72:], right)
	binary.LittleEndian.PutUint32(e[76:], child)
	return e
}

func TestMSIProvisionStream(t *testing.T) {
	placeholder := msiStreamName("Binary.MilvagoProvision")
	// Large enough to need DIFAT sectors in a version 3 file (over 109 FAT sectors).
	huge := bytes.Repeat([]byte("release payload "), 8<<20/16)
	for _, major := range []uint16{3, 4} {
		shift := uint16(9)
		if major == 4 {
			shift = 12
		}
		source := &cfbFile{major: major, shift: shift, entries: [][]byte{
			cfbTestEntry("Root Entry", 5, cfbFree, cfbFree, 1),
			cfbTestEntry(placeholder, 2, cfbFree, 2, cfbFree),
			cfbTestEntry("\x05SummaryInformation", 2, cfbFree, 3, cfbFree),
			cfbTestEntry(msiStreamName("Binary.Other"), 2, cfbFree, cfbFree, cfbFree),
		}, streams: map[int][]byte{1: []byte("{}"), 2: bytes.Repeat([]byte{7}, 5000), 3: huge}}
		raw, err := source.bytes()
		if err != nil {
			t.Fatal(err)
		}
		directory := t.TempDir()
		input, output := filepath.Join(directory, "in.msi"), filepath.Join(directory, "out.msi")
		if err = os.WriteFile(input, raw, 0600); err != nil {
			t.Fatal(err)
		}
		provision := []byte(`{"edition":"community","server_url":"https://example.test"}`)
		if err = setMSIBinaryStream(input, output, "MilvagoProvision", provision); err != nil {
			t.Fatal(err)
		}
		written, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		got, err := readCFB(written)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.streams[1], provision) || !bytes.Equal(got.streams[2], source.streams[2]) || !bytes.Equal(got.streams[3], huge) {
			t.Fatalf("v%d: provisioning must replace only its own stream", major)
		}
		for i, e := range got.entries[:4] {
			if !bytes.Equal(e[:116], source.entries[i][:116]) {
				t.Fatalf("v%d: directory entry %d changed", major, i)
			}
		}
		if err = setMSIBinaryStream(input, filepath.Join(directory, "x.msi"), "Absent", provision); err == nil {
			t.Fatal("a release without its placeholder must be refused")
		}
	}
	if _, err := readCFB(bytes.Repeat([]byte{0}, 4096)); err == nil {
		t.Fatal("non compound file accepted")
	}
}
