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
	raw, err := readConfined(source)
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

type cfbReader struct {
	raw   []byte
	size  int
	count uint32
	fat   []uint32
}

func parseCFBHeader(raw []byte) (*cfbFile, cfbReader, error) {
	le := binary.LittleEndian
	if len(raw) < 512 || !bytes.Equal(raw[:8], cfbSignature) || le.Uint16(raw[28:]) != 0xFFFE || le.Uint16(raw[32:]) != 6 || le.Uint32(raw[56:]) != cfbMiniCutoff {
		return nil, cfbReader{}, fmt.Errorf("not a compound file")
	}
	f := &cfbFile{major: le.Uint16(raw[26:]), shift: le.Uint16(raw[30:]), streams: map[int][]byte{}}
	if !(f.major == 3 && f.shift == 9) && !(f.major == 4 && f.shift == 12) {
		return nil, cfbReader{}, fmt.Errorf("unsupported compound file version")
	}
	size := 1 << f.shift
	if len(raw) < size {
		return nil, cfbReader{}, fmt.Errorf("truncated compound file")
	}
	return f, cfbReader{raw: raw, size: size, count: uint32((len(raw) - size) / size)}, nil
}

func (r cfbReader) sector(n uint32) ([]byte, error) {
	if n >= r.count {
		return nil, fmt.Errorf("sector out of range")
	}
	start := r.size * int(n+1)
	return r.raw[start : start+r.size], nil
}

func (r cfbReader) chain(start uint32, table []uint32, limit uint32) ([]uint32, error) {
	var out []uint32
	for n := start; n != cfbEndOfChain; n = table[n] {
		if n >= uint32(len(table)) || n >= limit || uint32(len(out)) >= limit {
			return nil, fmt.Errorf("broken sector chain")
		}
		out = append(out, n)
	}
	return out, nil
}

func (r cfbReader) read(start uint32) ([]byte, error) {
	sectors, e := r.chain(start, r.fat, r.count)
	if e != nil {
		return nil, e
	}
	out := make([]byte, 0, len(sectors)*r.size)
	for _, n := range sectors {
		sector, e := r.sector(n)
		if e != nil {
			return nil, e
		}
		out = append(out, sector...)
	}
	return out, nil
}

func (r cfbReader) readFAT() ([]uint32, error) {
	le := binary.LittleEndian
	perSector := r.size / 4
	var fatSectors []uint32
	for i := 0; i < cfbHeaderFAT; i++ {
		if n := le.Uint32(r.raw[76+4*i:]); n != cfbFree {
			fatSectors = append(fatSectors, n)
		}
	}
	for next, seen := le.Uint32(r.raw[68:]), uint32(0); next != cfbEndOfChain && next != cfbFree; seen++ {
		if seen >= r.count {
			return nil, fmt.Errorf("DIFAT loop")
		}
		sector, e := r.sector(next)
		if e != nil {
			return nil, e
		}
		for i := 0; i < perSector-1; i++ {
			if n := le.Uint32(sector[4*i:]); n != cfbFree {
				fatSectors = append(fatSectors, n)
			}
		}
		next = le.Uint32(sector[r.size-4:])
	}
	if uint32(len(fatSectors)) != le.Uint32(r.raw[44:]) {
		return nil, fmt.Errorf("FAT sector count mismatch")
	}
	fat := make([]uint32, 0, len(fatSectors)*perSector)
	for _, n := range fatSectors {
		sector, e := r.sector(n)
		if e != nil {
			return nil, e
		}
		for i := 0; i < perSector; i++ {
			fat = append(fat, le.Uint32(sector[4*i:]))
		}
	}
	return fat, nil
}

func (f *cfbFile) entrySize(entry []byte) uint64 {
	if f.major == 3 {
		return uint64(binary.LittleEndian.Uint32(entry[120:]))
	}
	return binary.LittleEndian.Uint64(entry[120:])
}

func (r cfbReader) readEntries(f *cfbFile) ([]byte, error) {
	le := binary.LittleEndian
	directory, e := r.read(le.Uint32(r.raw[48:]))
	if e != nil {
		return nil, e
	}
	for i := 0; i+cfbEntrySize <= len(directory); i += cfbEntrySize {
		f.entries = append(f.entries, append([]byte(nil), directory[i:i+cfbEntrySize]...))
	}
	if len(f.entries) == 0 || f.entries[0][66] != 5 {
		return nil, fmt.Errorf("compound file root missing")
	}
	root := f.entries[0]
	if f.entrySize(root) == 0 {
		return nil, nil
	}
	mini, e := r.read(le.Uint32(root[116:]))
	if e != nil {
		return nil, e
	}
	if uint64(len(mini)) < f.entrySize(root) {
		return nil, fmt.Errorf("mini stream truncated")
	}
	return mini, nil
}

func (r cfbReader) readMiniFAT() ([]uint32, error) {
	n := binary.LittleEndian.Uint32(r.raw[60:])
	if n == cfbEndOfChain || n == cfbFree {
		return nil, nil
	}
	table, e := r.read(n)
	if e != nil {
		return nil, e
	}
	var miniFAT []uint32
	for i := 0; i+4 <= len(table); i += 4 {
		miniFAT = append(miniFAT, binary.LittleEndian.Uint32(table[i:]))
	}
	return miniFAT, nil
}

func (r cfbReader) readEntryStream(entry []byte, length uint64, mini []byte, miniFAT []uint32) ([]byte, error) {
	le := binary.LittleEndian
	if length > uint64(len(r.raw)) {
		return nil, fmt.Errorf("stream too large")
	}
	var data []byte
	switch {
	case length == 0:
	case length < cfbMiniCutoff:
		miniCount := uint32(len(mini) / cfbMiniSize)
		sectors, e := r.chain(le.Uint32(entry[116:]), miniFAT, miniCount)
		if e != nil {
			return nil, e
		}
		for _, n := range sectors {
			data = append(data, mini[int(n)*cfbMiniSize:int(n+1)*cfbMiniSize]...)
		}
	default:
		var e error
		data, e = r.read(le.Uint32(entry[116:]))
		if e != nil {
			return nil, e
		}
	}
	if uint64(len(data)) < length {
		return nil, fmt.Errorf("stream truncated")
	}
	return data[:length], nil
}

func readCFB(raw []byte) (*cfbFile, error) {
	f, reader, e := parseCFBHeader(raw)
	if e != nil {
		return nil, e
	}
	reader.fat, e = reader.readFAT()
	if e != nil {
		return nil, e
	}
	mini, e := reader.readEntries(f)
	if e != nil {
		return nil, e
	}
	miniFAT, e := reader.readMiniFAT()
	if e != nil {
		return nil, e
	}
	for i, entry := range f.entries {
		if entry[66] != 2 {
			continue
		}
		data, e := reader.readEntryStream(entry, f.entrySize(entry), mini, miniFAT)
		if e != nil {
			return nil, e
		}
		f.streams[i] = data
	}
	return f, nil
}

func cfbCeil(n, d int) int { return (n + d - 1) / d }

type cfbWriter struct {
	file                                    *cfbFile
	size, perSector                         int
	entries                                 [][]byte
	mini                                    []byte
	miniFAT                                 []uint32
	large                                   []int
	dirSectors, miniFATSectors, miniSectors int
	fatSectors, difSectors, total           int
	fat                                     []uint32
	next                                    int
	dirStart, miniFATStart                  uint32
	out                                     []byte
}

func (b *cfbWriter) prepareEntries() {
	le := binary.LittleEndian
	b.entries = make([][]byte, len(b.file.entries))
	for i, entry := range b.file.entries {
		b.entries[i] = append([]byte(nil), entry...)
	}
	for len(b.entries)*cfbEntrySize%b.size != 0 {
		empty := make([]byte, cfbEntrySize)
		for _, at := range []int{68, 72, 76} {
			le.PutUint32(empty[at:], cfbFree)
		}
		b.entries = append(b.entries, empty)
	}
	// Small streams share the mini stream; large streams have dedicated sectors.
	for i := range b.entries {
		data, ok := b.file.streams[i]
		switch {
		case !ok:
		case len(data) == 0:
			le.PutUint32(b.entries[i][116:], cfbEndOfChain)
		case len(data) < cfbMiniCutoff:
			first := len(b.mini) / cfbMiniSize
			n := cfbCeil(len(data), cfbMiniSize)
			for j := 0; j < n; j++ {
				next := uint32(first + j + 1)
				if j == n-1 {
					next = cfbEndOfChain
				}
				b.miniFAT = append(b.miniFAT, next)
			}
			b.mini = append(b.mini, data...)
			b.mini = append(b.mini, make([]byte, n*cfbMiniSize-len(data))...)
			le.PutUint32(b.entries[i][116:], uint32(first))
		default:
			b.large = append(b.large, i)
		}
		if ok {
			le.PutUint64(b.entries[i][120:], uint64(len(data)))
		}
	}
}

func (b *cfbWriter) run(n int) uint32 {
	if n == 0 {
		return cfbEndOfChain
	}
	start := b.next
	for j := 0; j < n; j++ {
		b.fat[start+j] = uint32(start + j + 1)
	}
	b.fat[start+n-1] = cfbEndOfChain
	b.next += n
	return uint32(start)
}

func (b *cfbWriter) layoutSectors() {
	le := binary.LittleEndian
	b.dirSectors = len(b.entries) * cfbEntrySize / b.size
	b.miniFATSectors = cfbCeil(len(b.miniFAT)*4, b.size)
	b.miniSectors = cfbCeil(len(b.mini), b.size)
	content := b.dirSectors + b.miniFATSectors + b.miniSectors
	for _, i := range b.large {
		content += cfbCeil(len(b.file.streams[i]), b.size)
	}
	for b.fatSectors*b.perSector < content+b.fatSectors+b.difSectors {
		b.fatSectors++
		if b.fatSectors > cfbHeaderFAT {
			b.difSectors = cfbCeil(b.fatSectors-cfbHeaderFAT, b.perSector-1)
		}
	}
	b.total = content + b.fatSectors + b.difSectors
	b.fat = make([]uint32, b.fatSectors*b.perSector)
	for i := range b.fat {
		b.fat[i] = cfbFree
	}
	for ; b.next < b.fatSectors; b.next++ {
		b.fat[b.next] = cfbFATSector
	}
	for j := 0; j < b.difSectors; j, b.next = j+1, b.next+1 {
		b.fat[b.next] = cfbDIFSector
	}
	b.dirStart = b.run(b.dirSectors)
	b.miniFATStart = b.run(b.miniFATSectors)
	le.PutUint32(b.entries[0][116:], b.run(b.miniSectors))
	le.PutUint64(b.entries[0][120:], uint64(len(b.mini)))
	for _, i := range b.large {
		le.PutUint32(b.entries[i][116:], b.run(cfbCeil(len(b.file.streams[i]), b.size)))
	}
	if b.file.major == 3 {
		for _, entry := range b.entries {
			le.PutUint32(entry[124:], 0)
		}
	}
}

func (b *cfbWriter) writeHeader() {
	le := binary.LittleEndian
	h := b.out[:512]
	copy(h, cfbSignature)
	le.PutUint16(h[24:], 0x3E)
	le.PutUint16(h[26:], b.file.major)
	le.PutUint16(h[28:], 0xFFFE)
	le.PutUint16(h[30:], b.file.shift)
	le.PutUint16(h[32:], 6)
	if b.file.major == 4 {
		le.PutUint32(h[40:], uint32(b.dirSectors))
	}
	le.PutUint32(h[44:], uint32(b.fatSectors))
	le.PutUint32(h[48:], b.dirStart)
	le.PutUint32(h[56:], cfbMiniCutoff)
	le.PutUint32(h[60:], b.miniFATStart)
	le.PutUint32(h[64:], uint32(b.miniFATSectors))
	le.PutUint32(h[68:], cfbEndOfChain)
	if b.difSectors > 0 {
		le.PutUint32(h[68:], uint32(b.fatSectors))
	}
	le.PutUint32(h[72:], uint32(b.difSectors))
	for i := 0; i < cfbHeaderFAT; i++ {
		v := uint32(cfbFree)
		if i < b.fatSectors {
			v = uint32(i)
		}
		le.PutUint32(h[76+4*i:], v)
	}
}

func (b *cfbWriter) sectorAt(n int) []byte {
	return b.out[b.size*(n+1) : b.size*(n+2)]
}

func (b *cfbWriter) writeSectorTables() {
	le := binary.LittleEndian
	for i, value := range b.fat {
		le.PutUint32(b.sectorAt(i / b.perSector)[4*(i%b.perSector):], value)
	}
	for j := 0; j < b.difSectors; j++ {
		sector := b.sectorAt(b.fatSectors + j)
		for k := 0; k < b.perSector-1; k++ {
			value := uint32(cfbFree)
			if n := cfbHeaderFAT + j*(b.perSector-1) + k; n < b.fatSectors {
				value = uint32(n)
			}
			le.PutUint32(sector[4*k:], value)
		}
		link := uint32(cfbEndOfChain)
		if j+1 < b.difSectors {
			link = uint32(b.fatSectors + j + 1)
		}
		le.PutUint32(sector[b.size-4:], link)
	}
}

func (b *cfbWriter) writeStream(start uint32, data []byte) {
	if start != cfbEndOfChain {
		copy(b.out[b.size*(int(start)+1):], data)
	}
}

func (b *cfbWriter) writeStreams() {
	le := binary.LittleEndian
	b.writeStream(b.dirStart, bytes.Join(b.entries, nil))
	table := make([]byte, 4*len(b.miniFAT))
	for i, value := range b.miniFAT {
		le.PutUint32(table[4*i:], value)
	}
	if b.miniFATSectors > 0 {
		// Unused entries in the last mini FAT sector are marked free.
		tail := bytes.Repeat([]byte{0xFF}, b.miniFATSectors*b.size-len(table))
		b.writeStream(b.miniFATStart, append(table, tail...))
	}
	b.writeStream(le.Uint32(b.entries[0][116:]), b.mini)
	for _, i := range b.large {
		b.writeStream(le.Uint32(b.entries[i][116:]), b.file.streams[i])
	}
}

func (f *cfbFile) bytes() ([]byte, error) {
	builder := cfbWriter{file: f, size: 1 << f.shift}
	builder.perSector = builder.size / 4
	builder.prepareEntries()
	builder.layoutSectors()
	builder.out = make([]byte, builder.size*(builder.total+1))
	builder.writeHeader()
	builder.writeSectorTables()
	builder.writeStreams()
	return builder.out, nil
}
