package app

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"unicode/utf16"
)

// An MSI is an OLE compound file. The WiX template already carries the
// Binary.MilvagoProvision row and its placeholder stream; provisioning replaces
// that one stream's bytes and rewrites the container, keeping every directory
// entry (names, tree links, CLSIDs, timestamps) and every other stream intact.
// ponytail: whole file held in memory, bounded by installerBundleLimit and the two build slots.

const (
	cfbFree       = 0xFFFFFFFF
	cfbEndOfChain = 0xFFFFFFFE
	cfbFATSector  = 0xFFFFFFFD
	cfbDIFSector  = 0xFFFFFFFC
	cfbEntrySize  = 128
	cfbMiniSize   = 64
	cfbMiniCutoff = 4096
	cfbHeaderFAT  = 109
)

var cfbSignature = []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}

type cfbFile struct {
	major   uint16
	shift   uint16
	entries [][]byte // raw 128-byte directory entries, index-stable
	streams map[int][]byte
}

func setMSIBinaryStream(source, target, binaryName string, data []byte) error {
	raw, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	file, err := readCFB(raw)
	if err != nil {
		return err
	}
	name := msiStreamName("Binary." + binaryName)
	found := -1
	for i, entry := range file.entries {
		if entry[66] == 2 && cfbEntryName(entry) == name {
			if found >= 0 {
				return fmt.Errorf("duplicate MSI stream")
			}
			found = i
		}
	}
	// Only the template's placeholder is replaced: a release without it is refused, never extended.
	if found < 0 {
		return fmt.Errorf("MSI provision placeholder missing")
	}
	file.streams[found] = data
	out, err := file.bytes()
	if err != nil {
		return err
	}
	return os.WriteFile(target, out, 0600)
}

// msiStreamName applies Windows Installer's stream name compression: characters of
// [0-9A-Za-z._] pack in pairs into one code unit, others stay as they are.
func msiStreamName(in string) string {
	mime := func(c rune) int {
		switch {
		case c >= '0' && c <= '9':
			return int(c - '0')
		case c >= 'A' && c <= 'Z':
			return int(c-'A') + 10
		case c >= 'a' && c <= 'z':
			return int(c-'a') + 36
		case c == '.':
			return 62
		case c == '_':
			return 63
		}
		return -1
	}
	r := []rune(in)
	var out []rune
	for i := 0; i < len(r); i++ {
		m := mime(r[i])
		if m < 0 {
			out = append(out, r[i])
			continue
		}
		if i+1 < len(r) && mime(r[i+1]) >= 0 {
			out = append(out, rune(0x3800+m+mime(r[i+1])<<6))
			i++
		} else {
			out = append(out, rune(0x4800+m))
		}
	}
	return string(out)
}

func cfbEntryName(entry []byte) string {
	n := int(binary.LittleEndian.Uint16(entry[64:]))
	if n < 2 || n > 64 || n%2 != 0 {
		return ""
	}
	units := make([]uint16, n/2-1)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(entry[2*i:])
	}
	return string(utf16.Decode(units))
}

func readCFB(raw []byte) (*cfbFile, error) {
	le := binary.LittleEndian
	if len(raw) < 512 || !bytes.Equal(raw[:8], cfbSignature) || le.Uint16(raw[28:]) != 0xFFFE || le.Uint16(raw[32:]) != 6 || le.Uint32(raw[56:]) != cfbMiniCutoff {
		return nil, fmt.Errorf("not a compound file")
	}
	f := &cfbFile{major: le.Uint16(raw[26:]), shift: le.Uint16(raw[30:]), streams: map[int][]byte{}}
	if !(f.major == 3 && f.shift == 9) && !(f.major == 4 && f.shift == 12) {
		return nil, fmt.Errorf("unsupported compound file version")
	}
	size := 1 << f.shift
	if len(raw) < size {
		return nil, fmt.Errorf("truncated compound file")
	}
	count := uint32((len(raw) - size) / size)
	sector := func(n uint32) ([]byte, error) {
		if n >= count {
			return nil, fmt.Errorf("sector out of range")
		}
		start := size * int(n+1)
		return raw[start : start+size], nil
	}
	perSector := size / 4
	var fatSectors []uint32
	for i := 0; i < cfbHeaderFAT; i++ {
		if n := le.Uint32(raw[76+4*i:]); n != cfbFree {
			fatSectors = append(fatSectors, n)
		}
	}
	for next, seen := le.Uint32(raw[68:]), uint32(0); next != cfbEndOfChain && next != cfbFree; seen++ {
		if seen >= count {
			return nil, fmt.Errorf("DIFAT loop")
		}
		s, err := sector(next)
		if err != nil {
			return nil, err
		}
		for i := 0; i < perSector-1; i++ {
			if n := le.Uint32(s[4*i:]); n != cfbFree {
				fatSectors = append(fatSectors, n)
			}
		}
		next = le.Uint32(s[size-4:])
	}
	if uint32(len(fatSectors)) != le.Uint32(raw[44:]) {
		return nil, fmt.Errorf("FAT sector count mismatch")
	}
	fat := make([]uint32, 0, len(fatSectors)*perSector)
	for _, n := range fatSectors {
		s, err := sector(n)
		if err != nil {
			return nil, err
		}
		for i := 0; i < perSector; i++ {
			fat = append(fat, le.Uint32(s[4*i:]))
		}
	}
	chain := func(start uint32, table []uint32, limit uint32) ([]uint32, error) {
		var out []uint32
		for n := start; n != cfbEndOfChain; n = table[n] {
			if n >= uint32(len(table)) || n >= limit || uint32(len(out)) >= limit {
				return nil, fmt.Errorf("broken sector chain")
			}
			out = append(out, n)
		}
		return out, nil
	}
	read := func(start uint32) ([]byte, error) {
		sectors, err := chain(start, fat, count)
		if err != nil {
			return nil, err
		}
		out := make([]byte, 0, len(sectors)*size)
		for _, n := range sectors {
			s, err := sector(n)
			if err != nil {
				return nil, err
			}
			out = append(out, s...)
		}
		return out, nil
	}
	directory, err := read(le.Uint32(raw[48:]))
	if err != nil {
		return nil, err
	}
	for i := 0; i+cfbEntrySize <= len(directory); i += cfbEntrySize {
		f.entries = append(f.entries, append([]byte(nil), directory[i:i+cfbEntrySize]...))
	}
	if len(f.entries) == 0 || f.entries[0][66] != 5 {
		return nil, fmt.Errorf("compound file root missing")
	}
	entrySize := func(e []byte) uint64 {
		if f.major == 3 {
			return uint64(le.Uint32(e[120:]))
		}
		return le.Uint64(e[120:])
	}
	root := f.entries[0]
	var mini []byte
	if entrySize(root) > 0 {
		if mini, err = read(le.Uint32(root[116:])); err != nil {
			return nil, err
		}
		if uint64(len(mini)) < entrySize(root) {
			return nil, fmt.Errorf("mini stream truncated")
		}
	}
	var miniFAT []uint32
	if n := le.Uint32(raw[60:]); n != cfbEndOfChain && n != cfbFree {
		table, err := read(n)
		if err != nil {
			return nil, err
		}
		for i := 0; i+4 <= len(table); i += 4 {
			miniFAT = append(miniFAT, le.Uint32(table[i:]))
		}
	}
	miniCount := uint32(len(mini) / cfbMiniSize)
	for i, e := range f.entries {
		if e[66] != 2 {
			continue
		}
		length := entrySize(e)
		if length > uint64(len(raw)) {
			return nil, fmt.Errorf("stream too large")
		}
		var data []byte
		switch {
		case length == 0:
		case length < cfbMiniCutoff:
			sectors, err := chain(le.Uint32(e[116:]), miniFAT, miniCount)
			if err != nil {
				return nil, err
			}
			for _, n := range sectors {
				data = append(data, mini[int(n)*cfbMiniSize:int(n+1)*cfbMiniSize]...)
			}
		default:
			if data, err = read(le.Uint32(e[116:])); err != nil {
				return nil, err
			}
		}
		if uint64(len(data)) < length {
			return nil, fmt.Errorf("stream truncated")
		}
		f.streams[i] = data[:length]
	}
	return f, nil
}

func (f *cfbFile) bytes() ([]byte, error) {
	le := binary.LittleEndian
	size := 1 << f.shift
	perSector := size / 4
	ceil := func(n, d int) int { return (n + d - 1) / d }
	entries := make([][]byte, len(f.entries))
	for i, e := range f.entries {
		entries[i] = append([]byte(nil), e...)
	}
	for len(entries)*cfbEntrySize%size != 0 {
		empty := make([]byte, cfbEntrySize)
		for _, at := range []int{68, 72, 76} {
			le.PutUint32(empty[at:], cfbFree)
		}
		entries = append(entries, empty)
	}
	// Small streams go to the mini stream, the others to their own contiguous sectors.
	var mini []byte
	var miniFAT []uint32
	var large []int
	for i := range entries {
		data, ok := f.streams[i]
		switch {
		case !ok:
		case len(data) == 0:
			le.PutUint32(entries[i][116:], cfbEndOfChain)
		case len(data) < cfbMiniCutoff:
			first := len(mini) / cfbMiniSize
			n := ceil(len(data), cfbMiniSize)
			for j := 0; j < n; j++ {
				next := uint32(first + j + 1)
				if j == n-1 {
					next = cfbEndOfChain
				}
				miniFAT = append(miniFAT, next)
			}
			mini = append(mini, data...)
			mini = append(mini, make([]byte, n*cfbMiniSize-len(data))...)
			le.PutUint32(entries[i][116:], uint32(first))
		default:
			large = append(large, i)
		}
		if ok {
			le.PutUint64(entries[i][120:], uint64(len(data)))
		}
	}
	dirSectors := len(entries) * cfbEntrySize / size
	miniFATSectors := ceil(len(miniFAT)*4, size)
	miniSectors := ceil(len(mini), size)
	content := dirSectors + miniFATSectors + miniSectors
	for _, i := range large {
		content += ceil(len(f.streams[i]), size)
	}
	fatSectors, difSectors := 0, 0
	for fatSectors*perSector < content+fatSectors+difSectors {
		fatSectors++
		if fatSectors > cfbHeaderFAT {
			difSectors = ceil(fatSectors-cfbHeaderFAT, perSector-1)
		}
	}
	total := content + fatSectors + difSectors
	fat := make([]uint32, fatSectors*perSector)
	for i := range fat {
		fat[i] = cfbFree
	}
	next := 0
	run := func(n int) uint32 {
		if n == 0 {
			return cfbEndOfChain
		}
		start := next
		for j := 0; j < n; j++ {
			fat[start+j] = uint32(start + j + 1)
		}
		fat[start+n-1] = cfbEndOfChain
		next += n
		return uint32(start)
	}
	for ; next < fatSectors; next++ {
		fat[next] = cfbFATSector
	}
	for j := 0; j < difSectors; j, next = j+1, next+1 {
		fat[next] = cfbDIFSector
	}
	dirStart := run(dirSectors)
	miniFATStart := run(miniFATSectors)
	le.PutUint32(entries[0][116:], run(miniSectors))
	le.PutUint64(entries[0][120:], uint64(len(mini)))
	for _, i := range large {
		le.PutUint32(entries[i][116:], run(ceil(len(f.streams[i]), size)))
	}
	if f.major == 3 {
		for _, e := range entries {
			le.PutUint32(e[124:], 0)
		}
	}

	out := make([]byte, size*(total+1))
	h := out[:512]
	copy(h, cfbSignature)
	le.PutUint16(h[24:], 0x3E)
	le.PutUint16(h[26:], f.major)
	le.PutUint16(h[28:], 0xFFFE)
	le.PutUint16(h[30:], f.shift)
	le.PutUint16(h[32:], 6)
	if f.major == 4 {
		le.PutUint32(h[40:], uint32(dirSectors))
	}
	le.PutUint32(h[44:], uint32(fatSectors))
	le.PutUint32(h[48:], dirStart)
	le.PutUint32(h[56:], cfbMiniCutoff)
	le.PutUint32(h[60:], miniFATStart)
	le.PutUint32(h[64:], uint32(miniFATSectors))
	le.PutUint32(h[68:], cfbEndOfChain)
	if difSectors > 0 {
		le.PutUint32(h[68:], uint32(fatSectors))
	}
	le.PutUint32(h[72:], uint32(difSectors))
	for i := 0; i < cfbHeaderFAT; i++ {
		v := uint32(cfbFree)
		if i < fatSectors {
			v = uint32(i)
		}
		le.PutUint32(h[76+4*i:], v)
	}
	at := func(n int) []byte { return out[size*(n+1) : size*(n+2)] }
	for i, v := range fat {
		le.PutUint32(at(i / perSector)[4*(i%perSector):], v)
	}
	for j := 0; j < difSectors; j++ {
		s := at(fatSectors + j)
		for k := 0; k < perSector-1; k++ {
			v := uint32(cfbFree)
			if n := cfbHeaderFAT + j*(perSector-1) + k; n < fatSectors {
				v = uint32(n)
			}
			le.PutUint32(s[4*k:], v)
		}
		link := uint32(cfbEndOfChain)
		if j+1 < difSectors {
			link = uint32(fatSectors + j + 1)
		}
		le.PutUint32(s[size-4:], link)
	}
	write := func(start uint32, data []byte) {
		if start != cfbEndOfChain {
			copy(out[size*(int(start)+1):], data)
		}
	}
	write(dirStart, bytes.Join(entries, nil))
	table := make([]byte, 4*len(miniFAT))
	for i, v := range miniFAT {
		le.PutUint32(table[4*i:], v)
	}
	if miniFATSectors > 0 {
		// The unused tail of the last mini FAT sector must read as free.
		tail := bytes.Repeat([]byte{0xFF}, miniFATSectors*size-len(table))
		write(miniFATStart, append(table, tail...))
	}
	write(le.Uint32(entries[0][116:]), mini)
	for _, i := range large {
		write(le.Uint32(entries[i][116:]), f.streams[i])
	}
	return out, nil
}
