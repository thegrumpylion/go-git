package packfile

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"io"
	stdsync "sync"

	"github.com/go-git/go-git/v6/plumbing"
	format "github.com/go-git/go-git/v6/plumbing/format/config"
	"github.com/go-git/go-git/v6/plumbing/storer"
	"github.com/go-git/go-git/v6/utils/ioutil"
	"github.com/go-git/go-git/v6/utils/sync"
)

var (
	// ErrReferenceDeltaNotFound is returned when the reference delta is not
	// found.
	ErrReferenceDeltaNotFound = errors.New("reference delta not found")

	// ErrNotSeekableSource is returned when the source for the parser is not
	// seekable and a storage was not provided, so it can't be parsed.
	ErrNotSeekableSource = errors.New("parser source is not seekable and storage was not provided")

	// ErrDeltaNotCached is returned when the delta could not be found in cache.
	ErrDeltaNotCached = errors.New("delta could not be found in cache")

	// ErrParserConsumed is returned by Parse when called against a Parser
	// instance that has already been consumed by a prior Parse call,
	// whether that call returned successfully or with an error. Parsers
	// are single-shot; construct a new one per pack.
	ErrParserConsumed = errors.New("parser already consumed")
)

// maxObjectPreallocBytes caps the up-front size hint passed to
// bytes.Buffer.Grow when staging an object's contents, so a malformed length
// cannot trigger a huge or out-of-range allocation. The buffer still grows
// dynamically as data is written; this is purely a hint cap.
const maxObjectPreallocBytes = 1 << 30 // 1 GiB

// Match upstream Git's pack depth ceiling: pack-objects.h OE_DEPTH_BITS,
// enforced in builtin/pack-objects.c as (1 << OE_DEPTH_BITS) - 1.
const maxDeltaChainDepth = 4095

// growHint returns a non-negative int64 size, clamped to a sane upper bound,
// suitable for passing to bytes.Buffer.Grow.
func growHint(n int64) int {
	switch {
	case n <= 0:
		return 0
	case n > maxObjectPreallocBytes:
		return maxObjectPreallocBytes
	default:
		return int(n)
	}
}

// Parser decodes a packfile and calls any observer associated to it. Is used
// to generate indexes.
//
// A Parser is single-shot: Parse may be called at most once per
// instance. The cache maps and the per-delta parent pointers built up
// during a Parse call are not reset on entry, so a second call would
// observe the prior call's state — successful or not — and produce
// undefined results; the second call therefore returns
// ErrParserConsumed without running. Construct a new Parser for each
// pack you intend to decode.
type Parser struct {
	storage        storer.EncodedObjectStorer
	cache          *parserCache
	lowMemoryMode  bool
	highMemoryMode bool // asked for by option; wins over the seekable default

	// The delta walk's base cache in low memory mode: the contents
	// held, most recently used first, their bytes, the budget they
	// are trimmed to, and how many were derived again after eviction.
	lru       *list.List
	held      int64
	heldLimit int64
	derived   int
	passes    int // passes over the REF-deltas the walk never reached

	scanner   *Scanner
	observers []Observer
	hasher    plumbing.Hasher

	objectFormat format.ObjectFormat

	checksum plumbing.Hash
	m        stdsync.Mutex
	parsed   bool
}

// LowMemoryCapable is implemented by storage types that are capable of
// operating in low-memory mode.
type LowMemoryCapable interface {
	// LowMemoryMode defines whether the storage is able and willing for
	// the parser to operate in low-memory mode.
	LowMemoryMode() bool
}

// NewParser creates a new Parser.
// When a storage is set, the objects are written to storage as they
// are parsed.
func NewParser(data io.Reader, opts ...ParserOption) *Parser {
	p := &Parser{
		objectFormat: format.DefaultObjectFormat,
		heldLimit:    DefaultDeltaBaseCacheLimit,
		lru:          list.New(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}

	p.hasher = plumbing.NewHasher(p.objectFormat, plumbing.AnyObject, 0)
	var sopts []ScannerOption
	if p.objectFormat == format.SHA256 {
		sopts = append(sopts, WithSHA256())
	}

	p.scanner = NewScanner(data, sopts...)

	// Low memory mode needs a seekable source: contents are dropped and
	// inflated again from the pack on demand. Without a storage it is
	// the default over such a source, the delta walk holding only the
	// chain in flight; a storage decides for itself, and the option
	// asks for high memory mode in either case.
	p.lowMemoryMode = p.scanner.seeker != nil && !p.highMemoryMode
	if p.storage != nil {
		p.scanner.storage = p.storage

		lm, ok := p.storage.(LowMemoryCapable)
		p.lowMemoryMode = p.lowMemoryMode && ok && lm.LowMemoryMode()
	}
	p.scanner.lowMemoryMode = p.lowMemoryMode
	p.cache = newParserCache()

	return p
}

func (p *Parser) storeOrCache(oh *ObjectHeader) error {
	// Only need to store deltas, as the scanner already stored non-delta
	// objects.
	if p.storage != nil && oh.diskType.IsDelta() {
		w, err := p.storage.RawObjectWriter(oh.Type, oh.Size)
		if err != nil {
			return err
		}

		defer func() { _ = w.Close() }()

		_, err = ioutil.CopyBufferPool(w, oh.content)
		if err != nil {
			return err
		}
	}

	if p.cache != nil {
		p.cache.Add(oh)
	}

	if err := p.onInflatedObjectHeader(oh.Type, oh.Size, oh.Offset); err != nil {
		return err
	}

	return p.onInflatedObjectContent(oh.Hash, oh.Offset, oh.Crc32, nil)
}

func (p *Parser) resetCache(qty int) {
	if p.cache != nil {
		p.cache.Reset(qty)
	}
}

// Parse start decoding phase of the packfile.
func (p *Parser) Parse() (plumbing.Hash, error) {
	p.m.Lock()
	defer p.m.Unlock()

	if p.parsed {
		return plumbing.ZeroHash, ErrParserConsumed
	}
	p.parsed = true

	var pendingDeltas []*ObjectHeader
	var pendingDeltaREFs []*ObjectHeader

	for p.scanner.Scan() {
		data := p.scanner.Data()
		switch data.Section {
		case HeaderSection:
			header := data.Value().(Header)

			p.resetCache(int(header.ObjectsQty))
			_ = p.onHeader(header.ObjectsQty)

		case ObjectSection:
			oh := data.Value().(ObjectHeader)
			if oh.Type.IsDelta() {
				oh.Hash.ResetBySize(p.scanner.objectIDSize)
				switch oh.Type {
				case plumbing.OFSDeltaObject:
					pendingDeltas = append(pendingDeltas, &oh)
				case plumbing.REFDeltaObject:
					pendingDeltaREFs = append(pendingDeltaREFs, &oh)
				}
				continue
			}

			if p.lowMemoryMode && oh.content != nil {
				sync.PutBytesBuffer(oh.content)
				oh.content = nil
			}

			_ = p.storeOrCache(&oh)

		case FooterSection:
			p.checksum = data.Value().(plumbing.Hash)
		}
	}

	err := p.scanner.Error()
	if err != nil {
		if errors.Is(err, io.EOF) && p.scanner.objects == 0 {
			return plumbing.ZeroHash, ErrEmptyPackfile
		}
		return plumbing.ZeroHash, err
	}

	if err := p.resolveDeltas(pendingDeltas, pendingDeltaREFs); err != nil {
		return plumbing.ZeroHash, err
	}

	// Return to pool all objects used.
	go func() {
		for _, oh := range p.cache.oi {
			if oh.content != nil {
				sync.PutBytesBuffer(oh.content)
				oh.content = nil
			}
		}
	}()

	return p.checksum, p.onFooter(p.checksum)
}

func (p *Parser) ensureContent(oh *ObjectHeader) error {
	// Skip if this object already has the correct content.
	if !contentMissing(oh) && oh.content.Len() == int(oh.Size) && !oh.Hash.IsZero() {
		return nil
	}

	if oh.content == nil {
		oh.content = sync.GetBytesBuffer()
	}

	var err error
	switch {
	case !p.lowMemoryMode && oh.content != nil && oh.content.Len() > 0:
		source := oh.content
		oh.content = sync.GetBytesBuffer()

		defer sync.PutBytesBuffer(source)

		err = p.applyPatchBaseHeader(oh, source, oh.content, nil)
	case p.scanner.seeker != nil:
		deltaData := sync.GetBytesBuffer()
		defer sync.PutBytesBuffer(deltaData)

		err = p.scanner.inflateContent(oh.ContentOffset, deltaData, oh.deltaStreamSize)
		if err != nil {
			return fmt.Errorf("inflating content at offset %v: %w", oh.ContentOffset, err)
		}

		oh.content.Reset()
		err = p.applyPatchBaseHeader(oh, deltaData, oh.content, nil)
	default:
		return fmt.Errorf("can't ensure content: %w", plumbing.ErrObjectNotFound)
	}

	if err != nil {
		return fmt.Errorf("apply delta patch: %w", err)
	}
	p.hold(oh)
	return nil
}

// resolveDeltas walks the pack's delta DAG depth-first from each
// non-delta base, processing OFS and REF delta children of every parent
// together. Mirrors canonical Git's threaded_second_pass in
// builtin/index-pack.c[1], which advances both kinds of children from
// each in-progress parent in a single walk.
//
// In low memory mode the walk holds the contents of the chain in
// flight alone, and those within a budget: a parent's content stays
// in memory while its children are resolved against it and is
// released when the walk backs out of it; when what is held exceeds
// the delta base cache limit, the contents held longest are released
// first, and a parent released before its next child needs it is
// derived again by applying its chain from the nearest content still
// held — the shape of canonical git's delta base cache. Memory is
// bounded by the limit and one chain step, never by the pack's
// decoded size or a chain's depth, which is what lets a source with
// no storage behind it, the index built for a pack being written to
// disk, parse a pack of any size.
//
// Splitting REF and OFS resolution into separate passes (REF first, OFS
// second) is incorrect: a REF-delta whose base is an OFS-delta in the
// same pack would look up its base hash before the OFS-delta has been
// applied, since the OFS-delta's resolved hash is unknown at scan time.
// The lookup would then misclassify the in-pack base as a thin-pack
// external reference and the chain would fail to resolve.
//
// Any REF-delta not reached through the depth-first walk has a base
// outside this pack and is processed via the external-reference
// placeholder path. An OFS-delta whose recorded negative offset does
// not match any in-pack object header is rejected as malformed input.
//
// [1]: https://github.com/git/git/blob/v2.54.0/builtin/index-pack.c#L1103
func (p *Parser) resolveDeltas(ofsDeltas, refDeltas []*ObjectHeader) error {
	// Map sizes correspond to the count of distinct parent offsets /
	// hashes, not the count of delta entries. Real packs cluster many
	// children under one parent (chains and wide trees), so a hint
	// sized to len(deltas) consistently overshoots. Let the maps grow.
	ofsChildren := map[int64][]*ObjectHeader{}
	for _, d := range ofsDeltas {
		ofsChildren[d.OffsetReference] = append(ofsChildren[d.OffsetReference], d)
	}
	refChildren := map[plumbing.Hash][]*ObjectHeader{}
	for _, d := range refDeltas {
		refChildren[d.Reference] = append(refChildren[d.Reference], d)
	}

	var visit func(*ObjectHeader) error
	visit = func(parent *ObjectHeader) error {
		for _, c := range refChildren[parent.Hash] {
			// Two non-delta entries with identical content (or an
			// OFS-delta that resolves to the same hash as a non-delta
			// elsewhere in the pack) make this child reachable from
			// more than one parent; only the first reach resolves it.
			if c.parent != nil {
				continue
			}
			if err := p.processDelta(c); err != nil {
				return fmt.Errorf("processing ref-delta at offset %v: %w", c.Offset, err)
			}
			p.trim(c)
			if err := visit(c); err != nil {
				return err
			}
		}
		for _, c := range ofsChildren[parent.Offset] {
			if c.parent != nil {
				continue
			}
			if err := p.processDelta(c); err != nil {
				return fmt.Errorf("processing ofs-delta at offset %v: %w", c.Offset, err)
			}
			p.trim(c)
			if err := visit(c); err != nil {
				return err
			}
		}
		p.release(parent)
		return nil
	}

	// Snapshot the non-delta bases before walking, since processDelta
	// appends resolved deltas to p.cache.oi via storeOrCache. The
	// non-delta fraction of a real pack is small (typical 5-20%), so
	// preallocating to len(p.cache.oi) would waste most of the slot.
	var bases []*ObjectHeader
	for _, oh := range p.cache.oi {
		if !oh.Type.IsDelta() {
			bases = append(bases, oh)
		}
	}
	for _, base := range bases {
		if err := visit(base); err != nil {
			return err
		}
	}

	// A REF-delta the walk never reached names a base the walk did not
	// resolve before it: one outside the pack, or one resolved only
	// by a REF-delta listed after it. Each is tried in passes — a
	// base not found defers the delta to the next pass, since another
	// delta resolving in this one may be it — until a pass resolves
	// nothing, when the base is outside the pack and the storage
	// alike. A resolved one roots a chain of its own, walked the same
	// way from it.
	pending := refDeltas
	for len(pending) > 0 {
		p.passes++
		var rest []*ObjectHeader
		var deferred error
		var deferredAt int64
		progress := false
		for _, d := range pending {
			if !d.Hash.IsZero() {
				// Resolved through the walk since it was listed: a
				// delta's hash is known once it is.
				continue
			}
			err := p.processDelta(d)
			if errors.Is(err, ErrReferenceDeltaNotFound) || errors.Is(err, plumbing.ErrObjectNotFound) {
				p.forget(d)
				rest = append(rest, d)
				if deferred == nil {
					deferred, deferredAt = err, d.Offset
				}
				continue
			}
			if err != nil {
				return fmt.Errorf("processing ref-delta at offset %v: %w", d.Offset, err)
			}
			if err := visit(d); err != nil {
				return err
			}
			if d.parent.externalRef {
				p.release(d.parent)
			}
			progress = true
		}
		if !progress && len(rest) > 0 {
			return fmt.Errorf("processing ref-delta at offset %v: %w", deferredAt, deferred)
		}
		pending = rest
	}

	for _, d := range ofsDeltas {
		if !d.Hash.IsZero() {
			continue
		}
		return fmt.Errorf("processing ofs-delta at offset %v: %w", d.Offset, plumbing.ErrObjectNotFound)
	}

	return nil
}

// The delta base cache of low memory mode: the contents the walk
// holds, in the order they entered. A content enters when it is
// resolved or inflated and leaves when the walk backs out of it or
// when the cache is trimmed to its budget, the earliest entered
// first. What is held is the chain in flight, entered base first and
// released as the walk backs out, and a chain derived again is
// entered from its far end up: the earliest entered is the base end
// of the chain and the least recently used both, so the base the
// next child needs is the last to go, and no touch on use could
// order the entries otherwise. An evicted base is derived again from
// the nearest content still held when a child of it comes.

// hold enters a content into the cache, or re-accounts one whose
// buffer changed size.
func (p *Parser) hold(oh *ObjectHeader) {
	if !p.lowMemoryMode || oh.content == nil {
		return
	}
	size := int64(oh.content.Cap())
	if oh.heldElem == nil {
		oh.heldElem = p.lru.PushFront(oh)
	}
	p.held += size - oh.heldBytes
	oh.heldBytes = size
}

// release gives an object's content back to the pool, once nothing
// in the walk needs it — a parent whose children are all resolved,
// the placeholder of an external base — or once the cache is over
// its budget.
func (p *Parser) release(oh *ObjectHeader) {
	if !p.lowMemoryMode || oh == nil || oh.content == nil {
		return
	}
	if oh.heldElem != nil {
		p.lru.Remove(oh.heldElem)
		p.held -= oh.heldBytes
		oh.heldElem, oh.heldBytes = nil, 0
	}
	sync.PutBytesBuffer(oh.content)
	oh.content = nil
}

// trim releases the earliest entered contents while the cache is
// over its budget, keeping the one the walk is about to use — which
// a budget below one object would otherwise release too.
func (p *Parser) trim(keep *ObjectHeader) {
	for e := p.lru.Back(); e != nil && p.held > p.heldLimit; {
		prev := e.Prev()
		if oh := e.Value.(*ObjectHeader); oh != keep {
			p.release(oh)
		}
		e = prev
	}
}

// forget drops what a failed attempt at a delta left on it, so the
// next attempt starts from nothing: the content allocated for it,
// the placeholder parent, and the chain depth measured against that
// placeholder — one link, where the real chain may be any length.
// With no parent the delta counts as unresolved to the walk, which
// reaches it through its base the moment that resolves: a thin pack
// listing a chain leaf first resolves in one pass over the deferred
// deltas, not one pass per link.
func (p *Parser) forget(oh *ObjectHeader) {
	p.release(oh)
	oh.parent, oh.chainDepth = nil, 0
}

// contentMissing reports an object whose content is not in hand: none
// held, or a buffer drained into a storage and not filled again —
// an empty buffer is content only for an empty object.
func contentMissing(oh *ObjectHeader) bool {
	return oh.content == nil || (oh.content.Len() == 0 && oh.Size > 0)
}

// derive brings back the content of a delta the cache evicted: the
// chain of evicted deltas up to the nearest held content or the
// non-delta base is applied again from that end, one step at a time,
// each step held and the cache trimmed to its budget keeping the step
// the next one patches against.
func (p *Parser) derive(oh *ObjectHeader) error {
	var chain []*ObjectHeader
	cur := oh
	for ; cur != nil && contentMissing(cur) && cur.isDeltaOnDisk() && !cur.externalRef; cur = cur.parent {
		chain = append(chain, cur)
	}
	if cur == nil {
		return fmt.Errorf("deriving the delta at offset %v again: %w", oh.Offset, plumbing.ErrObjectNotFound)
	}
	for i := len(chain) - 1; i >= 0; i-- {
		step := chain[i]
		if err := p.ensureContent(step); err != nil {
			return fmt.Errorf("deriving the delta at offset %v again: %w", step.Offset, err)
		}
		p.derived++
		p.trim(step)
	}
	return nil
}

func (p *Parser) processDelta(oh *ObjectHeader) error {
	switch oh.Type {
	case plumbing.OFSDeltaObject:
		pa, ok := p.cache.oiByOffset[oh.OffsetReference]
		if !ok {
			return plumbing.ErrObjectNotFound
		}
		oh.parent = pa

	case plumbing.REFDeltaObject:
		pa, ok := p.cache.oiByHash[oh.Reference]
		if !ok {
			// can't find referenced object in this pack file
			// this must be a "thin" pack.
			oh.parent = &ObjectHeader{ // Placeholder parent
				Hash:        oh.Reference,
				externalRef: true, // mark as an external reference that must be resolved
				Type:        plumbing.AnyObject,
				diskType:    plumbing.AnyObject,
			}
		} else {
			oh.parent = pa
		}

	default:
		return fmt.Errorf("unsupported delta type: %v", oh.Type)
	}

	if err := checkDeltaChainDepth(oh); err != nil {
		return err
	}

	if err := p.ensureContent(oh); err != nil {
		return err
	}

	if oh.parent.externalRef {
		// A thin pack's external reference, resolved: the placeholder
		// is published so later REF-deltas naming the same hash chain
		// through it. Published on success alone, so an attempt that
		// failed — deferred for another pass — leaves nothing behind.
		p.cache.oiByHash[oh.Reference] = oh.parent
	}

	return p.storeOrCache(oh)
}

// checkDeltaChainDepth verifies that the delta chain rooted at oh
// stays within [maxDeltaChainDepth] links. The result is cached on
// [ObjectHeader.chainDepth] so a subsequent walk that crosses the
// same parent reuses the work — every entry on the chain ends up
// with its depth set once, which keeps the verification linear in
// the number of distinct objects rather than quadratic in the
// chain length. This mirrors the cached `oe->depth` field that
// upstream Git carries on the object entry in
// `builtin/pack-objects.c`.
func checkDeltaChainDepth(oh *ObjectHeader) error {
	if oh.chainDepth > 0 {
		return nil
	}
	var depth int
	for current := oh; current != nil && current.isDeltaOnDisk(); current = current.parent {
		if current.chainDepth > 0 {
			depth += current.chainDepth
			if depth > maxDeltaChainDepth {
				return fmt.Errorf("%w: delta chain depth exceeds %d", ErrMalformedPackfile, maxDeltaChainDepth)
			}
			break
		}
		depth++
		if depth > maxDeltaChainDepth {
			return fmt.Errorf("%w: delta chain depth exceeds %d", ErrMalformedPackfile, maxDeltaChainDepth)
		}
	}
	oh.chainDepth = depth
	return nil
}

func (oh *ObjectHeader) isDeltaOnDisk() bool {
	return oh.Type.IsDelta() || oh.diskType.IsDelta()
}

// parentReader returns a reader over the decompressed contents of the
// parent, along with how many bytes it holds. The size is reported
// separately because [io.ReaderAt] does not carry one, and callers
// sizing work from the parent need the bytes actually available rather
// than the size its header claims.
func (p *Parser) parentReader(parent *ObjectHeader) (io.ReaderAt, int64, error) {
	contents := func() (io.ReaderAt, int64, error) {
		b := parent.content.Bytes()
		return bytes.NewReader(b), int64(len(b)), nil
	}

	if parent.content != nil && parent.content.Len() > 0 {
		return contents()
	}

	// If parent is a Delta object, the inflated object must come
	// from either cache or storage, else we would need to inflate
	// it to then inflate the current object, which could go on
	// indefinitely.
	if p.storage != nil && !parent.Hash.IsZero() {
		obj, err := p.storage.EncodedObject(parent.Type, parent.Hash)
		if err == nil {
			// Ensure that external references have the correct type and size.
			parent.Type = obj.Type()
			parent.Size = obj.Size()
			r, err := obj.Reader()
			if err == nil {
				defer func() { _ = r.Close() }()

				if parent.content == nil {
					parent.content = sync.GetBytesBuffer()
				}
				parent.content.Grow(growHint(parent.Size))

				_, err = ioutil.CopyBufferPool(parent.content, r)
				if err == nil {
					// Filled from the storage: entered into the cache,
					// or re-accounted where its buffer grew.
					p.hold(parent)
					return contents()
				}
			}
		}
	}

	// If the parent is not an external ref and we don't have the
	// content offset, we won't be able to inflate via seeking through
	// the packfile.
	if !parent.externalRef && parent.ContentOffset == 0 {
		return nil, 0, plumbing.ErrObjectNotFound
	}

	// What sits at a delta parent's content offset is its delta
	// stream, not its content: a delta parent the cache evicted is
	// derived again from the nearest content still held.
	if parent.isDeltaOnDisk() && !parent.externalRef {
		if err := p.derive(parent); err != nil {
			return nil, 0, err
		}
		return contents()
	}

	// Not a seeker data source, so avoid seeking the content.
	if p.scanner.seeker == nil {
		return nil, 0, plumbing.ErrObjectNotFound
	}

	if parent.content == nil {
		parent.content = sync.GetBytesBuffer()
	}
	parent.content.Grow(growHint(parent.Size))

	err := p.scanner.inflateContent(parent.ContentOffset, parent.content, parent.Size)
	if err != nil {
		return nil, 0, ErrReferenceDeltaNotFound
	}
	p.hold(parent)
	return contents()
}

func (p *Parser) applyPatchBaseHeader(ota *ObjectHeader, delta *bytes.Buffer, target io.Writer, wh objectHeaderWriter) error {
	if target == nil {
		return fmt.Errorf("cannot apply patch against nil target")
	}

	parentContents, parentSz, err := p.parentReader(ota.parent)
	if err != nil {
		return err
	}

	typ := ota.Type
	if ota.Hash.IsZero() {
		typ = ota.parent.Type
	}

	sz, h, err := patchDeltaWriter(target, parentContents, parentSz, delta.Bytes(), typ, wh, p.objectFormat)
	if err != nil {
		return err
	}

	if ota.Hash.IsZero() {
		ota.Type = typ
		ota.Size = int64(sz)
		ota.Hash = h
	}

	return nil
}

func (p *Parser) forEachObserver(f func(o Observer) error) error {
	for _, o := range p.observers {
		if err := f(o); err != nil {
			return err
		}
	}
	return nil
}

func (p *Parser) onHeader(count uint32) error {
	return p.forEachObserver(func(o Observer) error {
		return o.OnHeader(count)
	})
}

func (p *Parser) onInflatedObjectHeader(
	t plumbing.ObjectType,
	objSize int64,
	pos int64,
) error {
	return p.forEachObserver(func(o Observer) error {
		return o.OnInflatedObjectHeader(t, objSize, pos)
	})
}

func (p *Parser) onInflatedObjectContent(
	h plumbing.Hash,
	pos int64,
	crc uint32,
	content []byte,
) error {
	return p.forEachObserver(func(o Observer) error {
		return o.OnInflatedObjectContent(h, pos, crc, content)
	})
}

func (p *Parser) onFooter(h plumbing.Hash) error {
	return p.forEachObserver(func(o Observer) error {
		return o.OnFooter(h)
	})
}
