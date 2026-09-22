package packfile_test

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"reflect"
	"runtime"
	"testing"

	billy "github.com/go-git/go-billy/v6"
	"github.com/go-git/go-billy/v6/osfs"
	fixtures "github.com/go-git/go-git-fixtures/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/internal/fixtureutil"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/cache"
	"github.com/go-git/go-git/v6/plumbing/format/config"
	"github.com/go-git/go-git/v6/plumbing/format/packfile"
	packutil "github.com/go-git/go-git/v6/plumbing/format/packfile/util"
	"github.com/go-git/go-git/v6/plumbing/storer"
	"github.com/go-git/go-git/v6/storage/filesystem"
	"github.com/go-git/go-git/v6/storage/memory"
	gogitbinary "github.com/go-git/go-git/v6/utils/binary"
)

func TestParserHashes(t *testing.T) {
	t.Parallel()

	packs := fixtures.ByTag("packfile-entries")
	require.GreaterOrEqual(t, len(packs), 2)

	packs.Run(t, func(t *testing.T, f *fixtures.Fixture) {
		t.Parallel()

		entries := fixtureutil.Entries(f)
		assertParserOutput(t, f, entries)
	})
}

func TestParserStorageModes(t *testing.T) {
	t.Parallel()

	// TODO: extend to SHA256 once the parser's low-memory path supports it.
	packs := fixtures.ByTag("packfile-entries").ByObjectFormat("sha1")
	require.GreaterOrEqual(t, len(packs), 2)

	packs.Run(t, func(t *testing.T, f *fixtures.Fixture) {
		t.Parallel()

		entries := fixtureutil.Entries(f)

		tests := []struct {
			name              string
			storage           storer.Storer
			option            packfile.ParserOption
			wantLowMemoryMode bool
		}{
			{
				name:              "without storage",
				wantLowMemoryMode: true,
			},
			{
				name:   "without storage and high memory mode",
				option: packfile.WithHighMemoryMode(),
			},
			{
				name:              "with filesystem storage",
				storage:           filesystem.NewStorage(osfs.New(t.TempDir()), cache.NewObjectLRUDefault()),
				wantLowMemoryMode: true,
			},
			{
				name:    "with storage and high memory mode",
				storage: filesystem.NewStorageWithOptions(osfs.New(t.TempDir()), cache.NewObjectLRUDefault(), filesystem.Options{HighMemoryMode: true}),
			},
			{
				name:    "with memory storage",
				storage: memory.NewStorage(),
			},
			{
				name:   "with memory storage and high memory mode",
				option: packfile.WithHighMemoryMode(),
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				if closer, ok := tc.storage.(io.Closer); ok {
					defer func() { _ = closer.Close() }()
				}

				obs := new(testObserver)
				pf, pfErr := f.Packfile()
				require.NoError(t, pfErr)

				opts := []packfile.ParserOption{
					packfile.WithScannerObservers(obs),
				}
				if tc.storage != nil {
					opts = append(opts, packfile.WithStorage(tc.storage))
				}
				if f.ObjectFormat == "sha256" {
					opts = append(opts, packfile.WithObjectFormat(config.SHA256))
				}
				if tc.option != nil {
					opts = append(opts, tc.option)
				}

				parser := packfile.NewParser(pf, opts...)

				field := reflect.ValueOf(parser).Elem().FieldByName("lowMemoryMode")
				assert.Equal(t, tc.wantLowMemoryMode, field.Bool())

				_, err := parser.Parse()
				require.NoError(t, err)

				assert.Equal(t, f.PackfileHash, obs.checksum)
				assert.Len(t, obs.objects, len(entries))

				for _, obj := range obs.objects {
					h := plumbing.NewHash(obj.hash)
					offset, ok := entries[h]
					assert.True(t, ok, "unexpected object %s", obj.hash)
					assert.Equal(t, offset, obj.offset, "offset mismatch for %s", obj.hash)
				}
			})
		}
	})
}

func assertParserOutput(t *testing.T, f *fixtures.Fixture, entries map[plumbing.Hash]int64) {
	t.Helper()

	obs := new(testObserver)
	pf, pfErr := f.Packfile()
	require.NoError(t, pfErr)

	opts := []packfile.ParserOption{packfile.WithScannerObservers(obs)}
	if f.ObjectFormat == "sha256" {
		opts = append(opts, packfile.WithObjectFormat(config.SHA256))
	}

	parser := packfile.NewParser(pf, opts...)

	_, err := parser.Parse()
	require.NoError(t, err)

	assert.Equal(t, f.PackfileHash, obs.checksum)
	assert.Len(t, obs.objects, len(entries))

	for _, obj := range obs.objects {
		h := plumbing.NewHash(obj.hash)
		offset, ok := entries[h]
		assert.True(t, ok, "unexpected object %s", obj.hash)
		assert.Equal(t, offset, obj.offset, "offset mismatch for %s", obj.hash)
	}
}

func TestParserMalformedPack(t *testing.T) {
	t.Parallel()
	f := fixtures.Basic().One()
	pf, pfErr := f.Packfile()
	require.NoError(t, pfErr)
	parser := packfile.NewParser(io.LimitReader(pf, 300))

	_, err := parser.Parse()
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestThinPack(t *testing.T) {
	t.Parallel()
	// Initialize an empty repository
	r, err := git.PlainInit(t.TempDir(), true)
	assert.NoError(t, err)

	// Try to parse a thin pack without having the required objects in the repo to
	// see if the correct errors are returned
	thinpack := fixtures.ByTag("thinpack").One()
	thinPf, thinPfErr := thinpack.Packfile()
	require.NoError(t, thinPfErr)
	parser := packfile.NewParser(thinPf, packfile.WithStorage(r.Storer)) // ParserWithStorage writes to the storer all parsed objects!

	_, err = parser.Parse()
	assert.ErrorIs(t, err, packfile.ErrReferenceDeltaNotFound)

	// start over with a clean repo
	_ = r.Close()
	r, err = git.PlainInit(t.TempDir(), true)
	assert.NoError(t, err)
	defer func() { _ = r.Close() }()

	// Now unpack a base packfile into our empty repo:
	f := fixtures.ByURL("https://github.com/spinnaker/spinnaker.git").One()
	w, err := r.Storer.(storer.PackfileWriter).PackfileWriter()
	assert.NoError(t, err)
	fPf, fPfErr := f.Packfile()
	require.NoError(t, fPfErr)
	_, err = io.Copy(w, fPf)
	assert.NoError(t, err)
	assert.NoError(t, w.Close())

	// Check that the test object that will come with our thin pack is *not* in the repo
	_, err = r.Storer.EncodedObject(plumbing.CommitObject, plumbing.NewHash(thinpack.Head))
	assert.ErrorIs(t, err, plumbing.ErrObjectNotFound)

	// Now unpack the thin pack:
	thinPf2, thinPf2Err := thinpack.Packfile()
	require.NoError(t, thinPf2Err)
	parser = packfile.NewParser(thinPf2, packfile.WithStorage(r.Storer)) // ParserWithStorage writes to the storer all parsed objects!

	h, err := parser.Parse()
	assert.NoError(t, err)
	assert.Equal(t, plumbing.NewHash("1288734cbe0b95892e663221d94b95de1f5d7be8"), h)

	// Check that our test object is now accessible
	_, err = r.Storer.EncodedObject(plumbing.CommitObject, plumbing.NewHash(thinpack.Head))
	assert.NoError(t, err)
}

func TestResolveExternalRefsInThinPack(t *testing.T) {
	t.Parallel()
	extRefsThinPack, err := fixtures.ByTag("codecommit").One().Packfile()
	require.NoError(t, err)

	parser := packfile.NewParser(extRefsThinPack)

	checksum, err := parser.Parse()
	assert.NoError(t, err)
	assert.NotEqual(t, checksum, plumbing.ZeroHash)
}

func TestResolveExternalRefs(t *testing.T) {
	t.Parallel()
	extRefsThinPack, err := fixtures.ByTag("delta-before-base").One().Packfile()
	require.NoError(t, err)

	parser := packfile.NewParser(extRefsThinPack)

	checksum, err := parser.Parse()
	assert.NoError(t, err)
	assert.NotEqual(t, plumbing.ZeroHash, checksum)
}

func TestMemoryResolveExternalRefs(t *testing.T) {
	t.Parallel()
	extRefsThinPack, err := fixtures.ByTag("delta-before-base").One().Packfile()
	require.NoError(t, err)

	parser := packfile.NewParser(extRefsThinPack, packfile.WithStorage(memory.NewStorage()))

	checksum, err := parser.Parse()
	assert.NoError(t, err)
	assert.NotEqual(t, plumbing.ZeroHash, checksum)
}

func BenchmarkParseBasic(b *testing.B) {
	for _, format := range []string{"sha1", "sha256"} {
		packs := fixtures.ByTag("packfile-entries").ByObjectFormat(format)
		if len(packs) == 0 {
			continue
		}

		f := packs.One()
		pf, err := f.Packfile()
		if err != nil {
			b.Fatal(err)
		}

		var scanOpts []packfile.ScannerOption
		var parseOpts []packfile.ParserOption
		if f.ObjectFormat == "sha256" {
			scanOpts = append(scanOpts, packfile.WithSHA256())
			parseOpts = append(parseOpts, packfile.WithObjectFormat(config.SHA256))
		}

		scanner := packfile.NewScanner(pf, scanOpts...)
		storage := filesystem.NewStorage(osfs.New(b.TempDir()), cache.NewObjectLRUDefault())
		b.Cleanup(func() {
			_ = storage.Close()
		})

		// TODO: storage modes for SHA256 once the parser's low-memory path supports it.
		if f.ObjectFormat != "sha256" {
			b.Run(format+"/with_storage", func(b *testing.B) {
				benchmarkParseBasic(b, pf, scanner, append(parseOpts, packfile.WithStorage(storage))...)
			})
			b.Run(format+"/with_memory_storage", func(b *testing.B) {
				benchmarkParseBasic(b, pf, scanner, append(parseOpts, packfile.WithStorage(memory.NewStorage()))...)
			})
		}
		b.Run(format+"/without_storage", func(b *testing.B) {
			benchmarkParseBasic(b, pf, scanner, parseOpts...)
		})
	}
}

func benchmarkParseBasic(b *testing.B,
	f billy.File, scanner *packfile.Scanner,
	opts ...packfile.ParserOption,
) {
	for i := 0; i < b.N; i++ {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			b.Fatal(err)
		}
		if err := scanner.Reset(); err != nil {
			b.Fatal(err)
		}
		parser := packfile.NewParser(scanner, opts...)

		checksum, err := parser.Parse()
		if err != nil {
			b.Fatal(err)
		}

		if checksum == plumbing.ZeroHash {
			b.Fatal("failed to parse")
		}
	}
}

func BenchmarkParse(b *testing.B) {
	for _, f := range fixtures.ByTag("packfile") {
		pff, pffErr := f.Packfile()
		if pffErr != nil {
			b.Fatal(pffErr)
		}
		scanner := packfile.NewScanner(pff)

		b.Run(f.URL, func(b *testing.B) {
			benchmarkParseBasic(b, pff, scanner)
		})
	}
}

// BenchmarkParseAlternatingDeltaChain exercises the depth-first delta walk
// on packs built from one non-delta base followed by N delta entries that
// alternate between OFS_DELTA and REF_DELTA, each derived from the
// previous entry. The fixture-based BenchmarkParse and BenchmarkParseBasic
// do not contain this shape — they cover pure OFS chains as produced by
// canonical Git's repacker — so without this target a regression in
// resolveDeltas would go unnoticed.
func BenchmarkParseAlternatingDeltaChain(b *testing.B) {
	for _, chainDepth := range []int{1, 4, 16, 64, 256} {
		pack := buildAlternatingDeltaChainPack(b, chainDepth)
		b.Run(fmt.Sprintf("depth=%d", chainDepth), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(pack)))
			for i := 0; i < b.N; i++ {
				parser := packfile.NewParser(bytes.NewReader(pack))
				if _, err := parser.Parse(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// buildAlternatingDeltaChainPack returns a pack with one non-delta base
// followed by chainDepth deltas. Odd-indexed deltas are OFS_DELTAs whose
// base is the immediately preceding entry; even-indexed deltas are
// REF_DELTAs whose base hash is the resolved hash of the preceding entry.
// This shape exercises every transition (non-delta → OFS, OFS → REF,
// REF → OFS, REF → REF) the parser's depth-first walk has to handle.
func buildAlternatingDeltaChainPack(tb testing.TB, chainDepth int) []byte {
	tb.Helper()

	contents := make([][]byte, chainDepth+1)
	contents[0] = []byte("benchmark base payload for the alternating delta chain")
	for i := 1; i <= chainDepth; i++ {
		next := make([]byte, len(contents[i-1]))
		copy(next, contents[i-1])
		next[i%len(next)] ^= 0xff
		contents[i] = next
	}

	hashes := make([]plumbing.Hash, chainDepth+1)
	for i := range contents {
		hashes[i] = blobHash(contents[i])
	}

	var pack bytes.Buffer
	sha := sha1.New()
	w := io.MultiWriter(&pack, sha)

	_, _ = w.Write([]byte("PACK"))
	_ = binary.Write(w, binary.BigEndian, uint32(2))
	_ = binary.Write(w, binary.BigEndian, uint32(chainDepth+1))

	offsets := make([]int64, chainDepth+1)

	// Entry 0: non-delta base blob.
	offsets[0] = int64(pack.Len())
	writePackObjectHeader(tb, w, plumbing.BlobObject, int64(len(contents[0])))
	writeZlibPayload(tb, w, contents[0])

	for i := 1; i <= chainDepth; i++ {
		offsets[i] = int64(pack.Len())
		delta := packfile.DiffDelta(contents[i-1], contents[i])
		if i%2 == 1 {
			writePackObjectHeader(tb, w, plumbing.OFSDeltaObject, int64(len(delta)))
			_ = gogitbinary.WriteVariableWidthInt(w, offsets[i]-offsets[i-1])
		} else {
			writePackObjectHeader(tb, w, plumbing.REFDeltaObject, int64(len(delta)))
			_, _ = hashes[i-1].WriteTo(w)
		}
		writeZlibPayload(tb, w, delta)
	}

	_, _ = pack.Write(sha.Sum(nil))
	return pack.Bytes()
}

type observerObject struct {
	hash   string
	otype  plumbing.ObjectType
	size   int64
	offset int64
	crc    uint32
}

type testObserver struct {
	count    uint32
	checksum string
	objects  []observerObject
	pos      map[int64]int
}

func (t *testObserver) OnHeader(count uint32) error {
	t.count = count
	t.pos = make(map[int64]int, count)
	return nil
}

func (t *testObserver) OnInflatedObjectHeader(otype plumbing.ObjectType, objSize, pos int64) error {
	o := t.get(pos)
	o.otype = otype
	o.size = objSize
	o.offset = pos

	t.put(pos, o)

	return nil
}

func (t *testObserver) OnInflatedObjectContent(h plumbing.Hash, pos int64, crc uint32, _ []byte) error {
	o := t.get(pos)
	o.hash = h.String()
	o.crc = crc

	t.put(pos, o)

	return nil
}

func (t *testObserver) OnFooter(h plumbing.Hash) error {
	t.checksum = h.String()
	return nil
}

func (t *testObserver) get(pos int64) observerObject {
	i, ok := t.pos[pos]
	if ok {
		return t.objects[i]
	}

	return observerObject{}
}

func (t *testObserver) put(pos int64, o observerObject) {
	i, ok := t.pos[pos]
	if ok {
		t.objects[i] = o
		return
	}

	t.pos[pos] = len(t.objects)
	t.objects = append(t.objects, o)
}

func TestChecksumMismatch(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp(t.TempDir(), "temp.pack")
	require.NoError(t, err)
	defer f.Close()

	basicPf, bpfErr := fixtures.Basic().One().Packfile()
	require.NoError(t, bpfErr)
	_, err = io.Copy(f, basicPf)
	require.NoError(t, err)

	_, err = f.Seek(-1, io.SeekEnd)
	require.NoError(t, err)

	_, err = f.Write([]byte{0})
	require.NoError(t, err)

	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)

	scanner := packfile.NewScanner(f)
	parser := packfile.NewParser(scanner)

	_, err = parser.Parse()
	require.ErrorContains(t, err, "checksum mismatch")
}

func TestMalformedPack(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp(t.TempDir(), "temp.pack")
	require.NoError(t, err)
	defer f.Close()

	basicPf2, bpf2Err := fixtures.Basic().One().Packfile()
	require.NoError(t, bpf2Err)
	_, err = io.Copy(f, io.LimitReader(basicPf2, 200))
	require.NoError(t, err)

	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)

	scanner := packfile.NewScanner(f)
	parser := packfile.NewParser(scanner)

	_, err = parser.Parse()
	require.ErrorContains(t, err, "malformed pack")
}

func TestParserRejectsOverflowingObjectHeader(t *testing.T) {
	t.Parallel()

	// Build a minimal pack whose first (and only) object header advertises
	// a variable-length size with enough continuation bytes that the
	// running shift would exceed what a uint64 can hold. The decoder must
	// reject this as malformed input rather than propagate a value that
	// later flows into a buffer allocation.
	var body bytes.Buffer
	body.WriteString("PACK")
	_ = binary.Write(&body, binary.BigEndian, uint32(2))
	_ = binary.Write(&body, binary.BigEndian, uint32(1))
	body.WriteByte(0x90) // type=commit, continuation=1, low nibble=0
	body.Write(bytes.Repeat([]byte{0x80}, 9))

	sum := sha1.Sum(body.Bytes())
	body.Write(sum[:])

	parser := packfile.NewParser(bytes.NewReader(body.Bytes()))

	_, err := parser.Parse()
	require.Error(t, err)
	require.ErrorContains(t, err, "malformed pack")
}

// writePackObjectHeader writes a packfile object header for an entry of
// the given type and uncompressed payload size in the variable-length
// encoding used by the pack format (4 bits of size in the first byte, 7
// bits per continuation byte).
func writePackObjectHeader(tb testing.TB, w io.Writer, typ plumbing.ObjectType, size int64) {
	tb.Helper()
	first := byte(typ)<<4 | byte(size&0x0F)
	rest := uint(size >> 4)
	if rest != 0 {
		first |= 0x80
	}
	_, _ = w.Write([]byte{first})
	if rest != 0 {
		_ = packutil.EncodeLEB128ToWriter(w, rest)
	}
}

// writeZlibPayload zlib-compresses payload and writes the result to w.
func writeZlibPayload(tb testing.TB, w io.Writer, payload []byte) {
	tb.Helper()
	zw := zlib.NewWriter(w)
	_, _ = zw.Write(payload)
	_ = zw.Close()
}

func blobHash(content []byte) plumbing.Hash {
	hasher := plumbing.NewHasher(config.SHA1, plumbing.BlobObject, int64(len(content)))
	_, _ = hasher.Write(content)
	return hasher.Sum()
}

// TestParserResolvesRefDeltaOfOfsDelta covers a pack containing a chain
// where a REF_DELTA's base is itself an OFS_DELTA. This shape is legal per
// the packfile spec and canonical Git's threaded_second_pass
// (builtin/index-pack.c:1103 in v2.54.0 94f057755b) walks delta children
// of both kinds depth-first from every non-delta base.
//
// A two-pass parser that resolves all REF_DELTAs first and OFS_DELTAs
// second would look up the REF_DELTA's base hash before the OFS_DELTA has
// been resolved (its hash is unknown at scan time), silently mark it as a
// thin-pack external reference, and then fail to materialise the leaf
// object.
//
// The probe runs under every storage mode the parser supports, because
// the storage-backed paths (parentReader at parser.go:333 and the
// LowMemoryMode branch in ensureContent) reload a resolved delta's
// contents through parent.Hash, and the new depth-first walk depends on
// that hash being set on the just-resolved OFS-delta before any REF-delta
// children look it up.
func TestParserResolvesRefDeltaOfOfsDelta(t *testing.T) {
	t.Parallel()

	pack, midHash, leafHash := buildRefOnOfsDeltaChainPack(t)

	tests := []struct {
		name    string
		storage storer.Storer
		option  packfile.ParserOption
	}{
		{
			name: "no storage",
		},
		{
			name:    "with memory storage",
			storage: memory.NewStorage(),
		},
		{
			name:    "with memory storage and high memory mode",
			storage: memory.NewStorage(),
			option:  packfile.WithHighMemoryMode(),
		},
		{
			name:    "with filesystem storage",
			storage: filesystem.NewStorage(osfs.New(t.TempDir()), cache.NewObjectLRUDefault()),
		},
		{
			name:    "with filesystem storage and high memory mode",
			storage: filesystem.NewStorageWithOptions(osfs.New(t.TempDir()), cache.NewObjectLRUDefault(), filesystem.Options{HighMemoryMode: true}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if closer, ok := tc.storage.(io.Closer); ok {
				defer func() { _ = closer.Close() }()
			}

			obs := new(testObserver)
			opts := []packfile.ParserOption{packfile.WithScannerObservers(obs)}
			if tc.storage != nil {
				opts = append(opts, packfile.WithStorage(tc.storage))
			}
			if tc.option != nil {
				opts = append(opts, tc.option)
			}

			parser := packfile.NewParser(bytes.NewReader(pack), opts...)

			_, err := parser.Parse()
			require.NoError(t, err, "parser must resolve REF-delta whose base is an in-pack OFS-delta")

			seen := make(map[plumbing.Hash]bool, len(obs.objects))
			for _, o := range obs.objects {
				seen[plumbing.NewHash(o.hash)] = true
			}
			assert.True(t, seen[midHash], "OFS-delta resolved hash %s missing from observer", midHash)
			assert.True(t, seen[leafHash], "REF-delta resolved hash %s missing from observer", leafHash)
		})
	}
}

// buildRefOnOfsDeltaChainPack returns a 3-entry pack with the shape
// [base blob, OFS-delta(base=blob), REF-delta(base=OFS-delta-hash)], along
// with the resolved hashes of the two delta entries.
func buildRefOnOfsDeltaChainPack(t *testing.T) (pack []byte, midHash, leafHash plumbing.Hash) {
	t.Helper()

	base := []byte("a stable base payload used by the OFS-delta entry")
	mid := []byte("a stable base payload modified by the OFS-delta entry")
	leaf := []byte("a stable base payload modified twice for the REF-delta")

	midHash = blobHash(mid)
	leafHash = blobHash(leaf)

	var buf bytes.Buffer
	h := sha1.New()
	w := io.MultiWriter(&buf, h)

	// PACK header: magic, version 2, 3 entries.
	_, _ = w.Write([]byte("PACK"))
	_ = binary.Write(w, binary.BigEndian, uint32(2))
	_ = binary.Write(w, binary.BigEndian, uint32(3))

	// Entry 1: non-delta base blob at offset 12.
	obj1Offset := int64(buf.Len())
	writePackObjectHeader(t, w, plumbing.BlobObject, int64(len(base)))
	writeZlibPayload(t, w, base)

	// Entry 2: OFS-delta whose base is entry 1.
	obj2Offset := int64(buf.Len())
	delta12 := packfile.DiffDelta(base, mid)
	writePackObjectHeader(t, w, plumbing.OFSDeltaObject, int64(len(delta12)))
	_ = gogitbinary.WriteVariableWidthInt(w, obj2Offset-obj1Offset)
	writeZlibPayload(t, w, delta12)

	// Entry 3: REF-delta whose base is entry 2's resolved hash.
	delta23 := packfile.DiffDelta(mid, leaf)
	writePackObjectHeader(t, w, plumbing.REFDeltaObject, int64(len(delta23)))
	_, _ = midHash.WriteTo(w)
	writeZlibPayload(t, w, delta23)

	// SHA-1 trailer over the pack body.
	_, _ = buf.Write(h.Sum(nil))

	return buf.Bytes(), midHash, leafHash
}

// TestParserBoundedMemoryWithoutStorage pins the memory bound of the
// delta walk over a seekable source with no storage behind it — the
// index built for a pack being written to disk: the heap never holds
// more than the chain in flight. The pack is one base with many wide
// children, each a delta resolving to distinct content of its own, so
// a walk that kept resolved contents until the end would hold them
// all; the heap is sampled at every resolved object, where the
// observer is called.
func TestParserBoundedMemoryWithoutStorage(t *testing.T) {
	const children, size = 96, 1 << 20
	pack, hashes := buildWideDeltaPack(t, children, size)
	total := int64(children) * size

	obs := &heapObserver{seen: map[plumbing.Hash]bool{}}
	parser := packfile.NewParser(bytes.NewReader(pack), packfile.WithScannerObservers(obs))
	_, err := parser.Parse()
	require.NoError(t, err)

	for _, h := range hashes {
		assert.True(t, obs.seen[h], "resolved hash %s missing from observer", h)
	}
	assert.Less(t, obs.peakGrowth, total/4,
		"the heap grew by %d bytes over a walk whose chains hold %d at most, the pack's %d decoded bytes retained", obs.peakGrowth, 2*size, total)
}

// TestParserDeltaBaseCacheLimit pins the walk's budget over a deep
// chain of large objects with no storage behind the parser: a chain of
// 40 deltas each resolving to a distinct megabyte holds 40 MiB in
// flight, and under a 4 MiB budget the walk releases contents from
// the base end and derives them again as their next child needs them
// — every hash still right, the heap growing by a small multiple of
// the budget rather than by the chain.
func TestParserDeltaBaseCacheLimit(t *testing.T) {
	const depth, size = 40, 1 << 20
	pack, hashes := buildDeltaChainPack(t, depth, size)

	obs := &heapObserver{seen: map[plumbing.Hash]bool{}}
	parser := packfile.NewParser(bytes.NewReader(pack),
		packfile.WithScannerObservers(obs),
		packfile.WithDeltaBaseCacheLimit(4<<20))
	_, err := parser.Parse()
	require.NoError(t, err)

	for _, h := range hashes {
		assert.True(t, obs.seen[h], "resolved hash %s missing from observer", h)
	}
	assert.Less(t, obs.peakGrowth, int64(depth*size/2),
		"the heap grew by %d bytes over a chain of %d holding %d, the budget %d", obs.peakGrowth, depth, depth*size, 4<<20)
}

// TestParserDerivesEvictedBases pins the derivation of an evicted
// base and the cost of it: a comb — a chain of deltas, then a leaf on
// every link of it listed after the chain — makes the walk back out
// of the whole chain and patch a leaf against each link on the way,
// under a budget a few links wide. Every hash is right, the heap
// stays within a few links, and the links are derived again fewer
// times than deriving every link from the base would take: a budget
// smaller than the chain makes the way back out cost a square of the
// depth over the budget whatever is evicted first, git's own delta
// base cache included; least recently used eviction keeps the links
// most lately derived, where evicting from the base end derives every
// link's whole chain again.
func TestParserDerivesEvictedBases(t *testing.T) {
	const depth, size = 48, 256 << 10
	pack, hashes := buildCombPack(t, depth, size)

	obs := &heapObserver{seen: map[plumbing.Hash]bool{}}
	parser := packfile.NewParser(bytes.NewReader(pack),
		packfile.WithScannerObservers(obs),
		packfile.WithDeltaBaseCacheLimit(4*size))
	_, err := parser.Parse()
	require.NoError(t, err)

	for _, h := range hashes {
		assert.True(t, obs.seen[h], "resolved hash %s missing from observer", h)
	}
	assert.Less(t, obs.peakGrowth, int64(depth*size/2),
		"the heap grew by %d bytes over a comb of %d links holding %d, the budget %d", obs.peakGrowth, depth, depth*size, 4*size)
	derived := reflect.ValueOf(parser).Elem().FieldByName("derived").Int()
	assert.Less(t, derived, int64(depth*depth/2-depth),
		"%d links derived again over a comb of %d: every link's whole chain, as evicting from the base end would", derived, depth)
	assert.Positive(t, derived, "no link derived again: the comb never left the budget")
}

// TestParserKeepsTheBaseInUse pins the cache's eviction order where
// it decides everything: a fan — one delta on the base, and many
// leaves on that delta — under a budget of two objects. Least
// recently used eviction keeps the delta every leaf patches against
// and evicts the leaves done with, so nothing is derived again;
// evicting the most recently used would evict the delta after every
// leaf and derive it again for the next.
func TestParserKeepsTheBaseInUse(t *testing.T) {
	const leaves, size = 32, 512 << 10
	pack, hashes := buildFanPack(t, leaves, size)

	obs := &heapObserver{seen: map[plumbing.Hash]bool{}}
	parser := packfile.NewParser(bytes.NewReader(pack),
		packfile.WithScannerObservers(obs),
		packfile.WithDeltaBaseCacheLimit(2*size))
	_, err := parser.Parse()
	require.NoError(t, err)

	for _, h := range hashes {
		assert.True(t, obs.seen[h], "resolved hash %s missing from observer", h)
	}
	derived := reflect.ValueOf(parser).Elem().FieldByName("derived").Int()
	assert.Zero(t, derived, "the delta the leaves patch against was evicted and derived again")
}

// buildFanPack returns a pack of one base blob, one OFS-delta on it,
// and leaves OFS-deltas on that delta, each resolving to size bytes
// unlike any other's, with the deltas' resolved hashes.
func buildFanPack(t *testing.T, leaves, size int) ([]byte, []plumbing.Hash) {
	t.Helper()

	rnd := rand.New(rand.NewPCG(7, 8))
	fill := func(b []byte) {
		for i := range b {
			b[i] = byte(rnd.UintN(256))
		}
	}
	base := make([]byte, size)
	fill(base)
	mid := make([]byte, size)
	fill(mid)

	var buf bytes.Buffer
	h := sha1.New()
	w := io.MultiWriter(&buf, h)
	_, _ = w.Write([]byte("PACK"))
	_ = binary.Write(w, binary.BigEndian, uint32(2))
	_ = binary.Write(w, binary.BigEndian, uint32(leaves+2))

	baseOffset := int64(buf.Len())
	writePackObjectHeader(t, w, plumbing.BlobObject, int64(len(base)))
	writeZlibPayload(t, w, base)

	hashes := []plumbing.Hash{blobHash(mid)}
	midDelta := packfile.DiffDelta(base, mid)
	midOffset := int64(buf.Len())
	writePackObjectHeader(t, w, plumbing.OFSDeltaObject, int64(len(midDelta)))
	_ = gogitbinary.WriteVariableWidthInt(w, midOffset-baseOffset)
	writeZlibPayload(t, w, midDelta)

	leaf := make([]byte, size)
	for i := 0; i < leaves; i++ {
		fill(leaf)
		hashes = append(hashes, blobHash(leaf))
		delta := packfile.DiffDelta(mid, leaf)
		offset := int64(buf.Len())
		writePackObjectHeader(t, w, plumbing.OFSDeltaObject, int64(len(delta)))
		_ = gogitbinary.WriteVariableWidthInt(w, offset-midOffset)
		writeZlibPayload(t, w, delta)
	}
	_, _ = buf.Write(h.Sum(nil))
	return buf.Bytes(), hashes
}

// TestParserZeroBudget pins the one content a budget never releases:
// the one the walk is about to use. Under a budget of zero a chain
// parses with nothing derived again, each link's content kept until
// its child is patched against it; releasing it too would derive
// every link's chain again.
func TestParserZeroBudget(t *testing.T) {
	const depth, size = 40, 64 << 10
	pack, hashes := buildDeltaChainPack(t, depth, size)

	obs := &heapObserver{seen: map[plumbing.Hash]bool{}}
	parser := packfile.NewParser(bytes.NewReader(pack),
		packfile.WithScannerObservers(obs),
		packfile.WithDeltaBaseCacheLimit(0))
	_, err := parser.Parse()
	require.NoError(t, err)

	for _, h := range hashes {
		assert.True(t, obs.seen[h], "resolved hash %s missing from observer", h)
	}
	derived := reflect.ValueOf(parser).Elem().FieldByName("derived").Int()
	assert.Zero(t, derived, "the content the next child patches against was released")
}

// TestParserDeferredDeltaDepth pins the chain depth guard over a
// thin pack listed leaf first: every REF-delta but the last names a
// delta listed after it, so each is deferred and resolved in a later
// pass, and the chain — deeper than the guard allows — is measured
// on the pass that resolves it, not on the attempt that deferred it
// against a placeholder one link deep.
func TestParserDeferredDeltaDepth(t *testing.T) {
	const depth = 4100
	pack, base := buildReverseRefChainPack(t, depth)

	st := memory.NewStorage()
	obj := &plumbing.MemoryObject{}
	obj.SetType(plumbing.BlobObject)
	_, err := obj.Write(base)
	require.NoError(t, err)
	_, err = st.SetEncodedObject(obj)
	require.NoError(t, err)

	parser := packfile.NewParser(bytes.NewReader(pack), packfile.WithStorage(st))
	_, err = parser.Parse()
	require.ErrorIs(t, err, packfile.ErrMalformedPackfile, "a chain %d deep listed leaf first resolved", depth)
}

// TestParserDeferredChainInOnePass pins the deferral leaving a delta
// unresolved to the walk: a thin pack of 500 REF-deltas listed leaf
// first resolves in one pass over the deferred deltas — the first
// pass resolves the one on the outside base and the walk cascades
// the chain from it — where a deferred delta still holding its
// placeholder parent would resolve one link per pass.
func TestParserDeferredChainInOnePass(t *testing.T) {
	const depth = 500
	pack, base := buildReverseRefChainPack(t, depth)

	st := memory.NewStorage()
	obj := &plumbing.MemoryObject{}
	obj.SetType(plumbing.BlobObject)
	_, err := obj.Write(base)
	require.NoError(t, err)
	_, err = st.SetEncodedObject(obj)
	require.NoError(t, err)

	obs := &heapObserver{seen: map[plumbing.Hash]bool{}}
	parser := packfile.NewParser(bytes.NewReader(pack), packfile.WithStorage(st), packfile.WithScannerObservers(obs))
	_, err = parser.Parse()
	require.NoError(t, err)
	assert.Len(t, obs.seen, depth)
	passes := reflect.ValueOf(parser).Elem().FieldByName("passes").Int()
	assert.LessOrEqual(t, passes, int64(2), "%d passes over a chain of %d deferred deltas", passes, depth)
}

// TestParserDerivesWhenStorageFails pins derivation as the fallback
// for a base whose buffer a storage drained and cannot fill again:
// the storage's reads fail, the parse still resolves every hash by
// deriving the evicted bases from the pack.
func TestParserDerivesWhenStorageFails(t *testing.T) {
	const depth, size = 8, 64 << 10
	pack, hashes := buildDeltaChainPack(t, depth, size)

	st := &unreadableStorage{Storage: filesystem.NewStorage(osfs.New(t.TempDir()), cache.NewObjectLRU(size))}
	obs := &heapObserver{seen: map[plumbing.Hash]bool{}}
	parser := packfile.NewParser(bytes.NewReader(pack),
		packfile.WithScannerObservers(obs),
		packfile.WithStorage(st),
		packfile.WithDeltaBaseCacheLimit(size))
	_, err := parser.Parse()
	require.NoError(t, err)
	for _, h := range hashes {
		assert.True(t, obs.seen[h], "resolved hash %s missing from observer", h)
	}
}

// unreadableStorage stores objects and refuses to read them back.
type unreadableStorage struct {
	*filesystem.Storage
}

func (s *unreadableStorage) EncodedObject(plumbing.ObjectType, plumbing.Hash) (plumbing.EncodedObject, error) {
	return nil, plumbing.ErrObjectNotFound
}

// buildReverseRefChainPack returns a thin pack of depth REF-deltas
// listed leaf first — each on the resolved hash of the one listed
// after it, the last on a base outside the pack — and that base.
func buildReverseRefChainPack(t *testing.T, depth int) ([]byte, []byte) {
	t.Helper()

	contents := make([][]byte, depth+1)
	contents[0] = []byte("the base outside the pack")
	for i := 1; i <= depth; i++ {
		contents[i] = append(append([]byte{}, contents[i-1]...), []byte(fmt.Sprintf(" %d", i))...)
	}

	var buf bytes.Buffer
	h := sha1.New()
	w := io.MultiWriter(&buf, h)
	_, _ = w.Write([]byte("PACK"))
	_ = binary.Write(w, binary.BigEndian, uint32(2))
	_ = binary.Write(w, binary.BigEndian, uint32(depth))
	for i := depth; i >= 1; i-- {
		delta := packfile.DiffDelta(contents[i-1], contents[i])
		writePackObjectHeader(t, w, plumbing.REFDeltaObject, int64(len(delta)))
		baseHash := blobHash(contents[i-1])
		_, _ = baseHash.WriteTo(w)
		writeZlibPayload(t, w, delta)
	}
	_, _ = buf.Write(h.Sum(nil))
	return buf.Bytes(), contents[0]
}

// TestParserBudgetWithStorage pins the budget over a storage-backed
// parse: with a filesystem storage behind the parser the contents
// the walk holds are still trimmed to the budget, the account kept
// as a stored object's buffer is drained and filled again.
func TestParserBudgetWithStorage(t *testing.T) {
	const depth, size = 40, 1 << 20
	pack, hashes := buildDeltaChainPack(t, depth, size)

	// The storage's own object cache is kept to two objects: the bound
	// under test is the parser's.
	st := filesystem.NewStorage(osfs.New(t.TempDir()), cache.NewObjectLRU(2*size))
	obs := &heapObserver{seen: map[plumbing.Hash]bool{}}
	parser := packfile.NewParser(bytes.NewReader(pack),
		packfile.WithScannerObservers(obs),
		packfile.WithStorage(st),
		packfile.WithDeltaBaseCacheLimit(4<<20))
	_, err := parser.Parse()
	require.NoError(t, err)

	for _, h := range hashes {
		assert.True(t, obs.seen[h], "resolved hash %s missing from observer", h)
	}
	assert.Less(t, obs.peakGrowth, int64(depth*size/2),
		"the heap grew by %d bytes over a chain of %d holding %d, the budget %d", obs.peakGrowth, depth, depth*size, 4<<20)
}

// TestParserEmptyDeltaBase pins a delta resolving to empty content
// serving as the base of another: the empty content is content in
// hand, not content missing.
func TestParserEmptyDeltaBase(t *testing.T) {
	base := []byte("a base with content")
	leaf := []byte("grown back from nothing")
	pack := buildOfsChainPack(t, base, [][]byte{{}, leaf})

	obs := &heapObserver{seen: map[plumbing.Hash]bool{}}
	parser := packfile.NewParser(bytes.NewReader(pack), packfile.WithScannerObservers(obs))
	_, err := parser.Parse()
	require.NoError(t, err)
	assert.True(t, obs.seen[blobHash(nil)], "the empty object missing from observer")
	assert.True(t, obs.seen[blobHash(leaf)], "the leaf on the empty base missing from observer")
}

// TestParserExternalRootOrder pins a thin pack whose REF-deltas are
// listed leaf first: d2 on d1's resolved hash before d1 on a base
// outside the pack. d2's base is unknown until d1 resolves, so the
// walk resolves d1 first and d2 after it, whichever order the pack
// lists them in.
func TestParserExternalRootOrder(t *testing.T) {
	base := []byte("a base kept outside the pack")
	mid := []byte("a base kept outside the pack, changed once")
	leaf := []byte("a base kept outside the pack, changed twice")
	pack := buildLeafFirstThinPack(t, base, mid, leaf)

	st := memory.NewStorage()
	obj := &plumbing.MemoryObject{}
	obj.SetType(plumbing.BlobObject)
	_, err := obj.Write(base)
	require.NoError(t, err)
	_, err = st.SetEncodedObject(obj)
	require.NoError(t, err)

	obs := &heapObserver{seen: map[plumbing.Hash]bool{}}
	parser := packfile.NewParser(bytes.NewReader(pack), packfile.WithScannerObservers(obs), packfile.WithStorage(st))
	_, err = parser.Parse()
	require.NoError(t, err)
	assert.True(t, obs.seen[blobHash(mid)], "the delta on the outside base missing from observer")
	assert.True(t, obs.seen[blobHash(leaf)], "the delta listed before its base missing from observer")
}

// buildCombPack returns a pack of one base blob, a chain of depth
// OFS-deltas on it, and after the chain one small OFS-delta leaf on
// every link, with every delta's resolved hash.
func buildCombPack(t *testing.T, depth, size int) ([]byte, []plumbing.Hash) {
	t.Helper()

	rnd := rand.New(rand.NewPCG(5, 6))
	fill := func(b []byte) {
		for i := range b {
			b[i] = byte(rnd.UintN(256))
		}
	}
	prev := make([]byte, size)
	fill(prev)

	var buf bytes.Buffer
	h := sha1.New()
	w := io.MultiWriter(&buf, h)
	_, _ = w.Write([]byte("PACK"))
	_ = binary.Write(w, binary.BigEndian, uint32(2))
	_ = binary.Write(w, binary.BigEndian, uint32(2*depth+1))

	prevOffset := int64(buf.Len())
	writePackObjectHeader(t, w, plumbing.BlobObject, int64(len(prev)))
	writeZlibPayload(t, w, prev)

	var hashes []plumbing.Hash
	links := make([][]byte, 0, depth)
	offsets := make([]int64, 0, depth)
	for i := 0; i < depth; i++ {
		next := make([]byte, size)
		fill(next)
		hashes = append(hashes, blobHash(next))
		delta := packfile.DiffDelta(prev, next)
		offset := int64(buf.Len())
		writePackObjectHeader(t, w, plumbing.OFSDeltaObject, int64(len(delta)))
		_ = gogitbinary.WriteVariableWidthInt(w, offset-prevOffset)
		writeZlibPayload(t, w, delta)
		links, offsets = append(links, next), append(offsets, offset)
		prev, prevOffset = next, offset
	}
	for i, link := range links {
		leaf := append(append([]byte{}, link...), []byte(fmt.Sprintf(" leaf %d", i))...)
		hashes = append(hashes, blobHash(leaf))
		delta := packfile.DiffDelta(link, leaf)
		offset := int64(buf.Len())
		writePackObjectHeader(t, w, plumbing.OFSDeltaObject, int64(len(delta)))
		_ = gogitbinary.WriteVariableWidthInt(w, offset-offsets[i])
		writeZlibPayload(t, w, delta)
	}
	_, _ = buf.Write(h.Sum(nil))
	return buf.Bytes(), hashes
}

// buildOfsChainPack returns a pack of one base blob and a chain of
// OFS-deltas resolving to the given contents in order, each on the
// one before.
func buildOfsChainPack(t *testing.T, base []byte, chain [][]byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	h := sha1.New()
	w := io.MultiWriter(&buf, h)
	_, _ = w.Write([]byte("PACK"))
	_ = binary.Write(w, binary.BigEndian, uint32(2))
	_ = binary.Write(w, binary.BigEndian, uint32(len(chain)+1))

	prev, prevOffset := base, int64(buf.Len())
	writePackObjectHeader(t, w, plumbing.BlobObject, int64(len(base)))
	writeZlibPayload(t, w, base)
	for _, next := range chain {
		delta := packfile.DiffDelta(prev, next)
		offset := int64(buf.Len())
		writePackObjectHeader(t, w, plumbing.OFSDeltaObject, int64(len(delta)))
		_ = gogitbinary.WriteVariableWidthInt(w, offset-prevOffset)
		writeZlibPayload(t, w, delta)
		prev, prevOffset = next, offset
	}
	_, _ = buf.Write(h.Sum(nil))
	return buf.Bytes()
}

// buildLeafFirstThinPack returns a thin pack of two REF-deltas listed
// leaf first: the delta from mid to leaf, then the delta from base
// to mid, base itself outside the pack.
func buildLeafFirstThinPack(t *testing.T, base, mid, leaf []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	h := sha1.New()
	w := io.MultiWriter(&buf, h)
	_, _ = w.Write([]byte("PACK"))
	_ = binary.Write(w, binary.BigEndian, uint32(2))
	_ = binary.Write(w, binary.BigEndian, uint32(2))

	d2 := packfile.DiffDelta(mid, leaf)
	writePackObjectHeader(t, w, plumbing.REFDeltaObject, int64(len(d2)))
	midHash := blobHash(mid)
	_, _ = midHash.WriteTo(w)
	writeZlibPayload(t, w, d2)

	d1 := packfile.DiffDelta(base, mid)
	writePackObjectHeader(t, w, plumbing.REFDeltaObject, int64(len(d1)))
	baseHash := blobHash(base)
	_, _ = baseHash.WriteTo(w)
	writeZlibPayload(t, w, d1)

	_, _ = buf.Write(h.Sum(nil))
	return buf.Bytes()
}

// buildDeltaChainPack returns a pack of one base blob and a chain of n
// OFS-deltas, each on the one before and each resolving to size bytes
// of content unlike any other's, with the chain's resolved hashes.
func buildDeltaChainPack(t *testing.T, n, size int) ([]byte, []plumbing.Hash) {
	t.Helper()

	rnd := rand.New(rand.NewPCG(3, 4))
	fill := func(b []byte) {
		for i := range b {
			b[i] = byte(rnd.UintN(256))
		}
	}
	prev := make([]byte, size)
	fill(prev)

	var buf bytes.Buffer
	h := sha1.New()
	w := io.MultiWriter(&buf, h)
	_, _ = w.Write([]byte("PACK"))
	_ = binary.Write(w, binary.BigEndian, uint32(2))
	_ = binary.Write(w, binary.BigEndian, uint32(n+1))

	prevOffset := int64(buf.Len())
	writePackObjectHeader(t, w, plumbing.BlobObject, int64(len(prev)))
	writeZlibPayload(t, w, prev)

	hashes := make([]plumbing.Hash, 0, n)
	for i := 0; i < n; i++ {
		next := make([]byte, size)
		fill(next)
		hashes = append(hashes, blobHash(next))
		delta := packfile.DiffDelta(prev, next)
		offset := int64(buf.Len())
		writePackObjectHeader(t, w, plumbing.OFSDeltaObject, int64(len(delta)))
		_ = gogitbinary.WriteVariableWidthInt(w, offset-prevOffset)
		writeZlibPayload(t, w, delta)
		prev, prevOffset = next, offset
	}
	_, _ = buf.Write(h.Sum(nil))
	return buf.Bytes(), hashes
}

// heapObserver samples the live heap's growth since its first call at
// every resolved object, collecting first so garbage the collector has
// not yet reached counts for nothing.
type heapObserver struct {
	base       uint64
	peakGrowth int64
	seen       map[plumbing.Hash]bool
}

func (o *heapObserver) OnHeader(uint32) error { return nil }
func (o *heapObserver) OnInflatedObjectHeader(plumbing.ObjectType, int64, int64) error {
	return nil
}
func (o *heapObserver) OnFooter(plumbing.Hash) error { return nil }

func (o *heapObserver) OnInflatedObjectContent(h plumbing.Hash, _ int64, _ uint32, _ []byte) error {
	o.seen[h] = true
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	if o.base == 0 {
		o.base = ms.HeapAlloc
	}
	if g := int64(ms.HeapAlloc) - int64(o.base); g > o.peakGrowth {
		o.peakGrowth = g
	}
	return nil
}

// buildWideDeltaPack returns a pack of one base blob and n OFS-delta
// children of it, each resolving to size bytes of content unlike any
// other's, with the children's resolved hashes.
func buildWideDeltaPack(t *testing.T, n, size int) ([]byte, []plumbing.Hash) {
	t.Helper()

	rnd := rand.New(rand.NewPCG(1, 2))
	fill := func(b []byte) {
		for i := range b {
			b[i] = byte(rnd.UintN(256))
		}
	}
	base := make([]byte, size)
	fill(base)

	var buf bytes.Buffer
	h := sha1.New()
	w := io.MultiWriter(&buf, h)
	_, _ = w.Write([]byte("PACK"))
	_ = binary.Write(w, binary.BigEndian, uint32(2))
	_ = binary.Write(w, binary.BigEndian, uint32(n+1))

	baseOffset := int64(buf.Len())
	writePackObjectHeader(t, w, plumbing.BlobObject, int64(len(base)))
	writeZlibPayload(t, w, base)

	hashes := make([]plumbing.Hash, 0, n)
	child := make([]byte, size)
	for i := 0; i < n; i++ {
		fill(child)
		hashes = append(hashes, blobHash(child))
		delta := packfile.DiffDelta(base, child)
		offset := int64(buf.Len())
		writePackObjectHeader(t, w, plumbing.OFSDeltaObject, int64(len(delta)))
		_ = gogitbinary.WriteVariableWidthInt(w, offset-baseOffset)
		writeZlibPayload(t, w, delta)
	}
	_, _ = buf.Write(h.Sum(nil))
	return buf.Bytes(), hashes
}

// TestParserParseRejectsSecondCall pins the single-shot Parser invariant
// documented on the Parser type: once Parse has been called (whether it
// returned successfully or with an error mid-walk), a subsequent call
// against the same instance must fail loudly rather than silently
// running over the prior call's leftover state.
func TestParserParseRejectsSecondCall(t *testing.T) {
	t.Parallel()

	// Build a minimal valid pack with zero objects (header + count=0 +
	// SHA-1 trailer over the header). Parse accepts this and returns
	// the pack checksum; the test then asserts the second call against
	// the same Parser is rejected.
	var buf bytes.Buffer
	h := sha1.New()
	w := io.MultiWriter(&buf, h)
	_, _ = w.Write([]byte{'P', 'A', 'C', 'K'})
	_ = binary.Write(w, binary.BigEndian, uint32(2))
	_ = binary.Write(w, binary.BigEndian, uint32(0))
	_, _ = buf.Write(h.Sum(nil))

	p := packfile.NewParser(bytes.NewReader(buf.Bytes()))
	_, err := p.Parse()
	require.NoError(t, err, "first Parse on the empty-object pack should succeed")

	_, err = p.Parse()
	assert.ErrorIs(t, err, packfile.ErrParserConsumed, "second Parse must return ErrParserConsumed")
}
