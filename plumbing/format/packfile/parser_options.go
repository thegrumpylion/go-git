package packfile

import (
	"github.com/go-git/go-git/v6/plumbing/format/config"
	"github.com/go-git/go-git/v6/plumbing/storer"
)

// ParserOption configures a Parser.
type ParserOption func(*Parser)

// WithStorage sets the storage to be used while parsing a pack file.
func WithStorage(storage storer.EncodedObjectStorer) ParserOption {
	return func(p *Parser) {
		p.storage = storage
	}
}

// WithScannerObservers sets the observers to be notified during the
// scanning or parsing of a pack file. The scanner is responsible for
// notifying observers around general pack file information, such as
// header and footer. The scanner also notifies object headers for
// non-delta objects.
//
// Delta objects are notified as part of the parser logic.
func WithScannerObservers(ob ...Observer) ParserOption {
	return func(p *Parser) {
		p.observers = ob
	}
}

// WithObjectFormat sets the object format for the parser.
func WithObjectFormat(of config.ObjectFormat) ParserOption {
	return func(p *Parser) {
		if of == config.UnsetObjectFormat {
			of = config.DefaultObjectFormat
		}
		p.objectFormat = of
	}
}

// WithHighMemoryMode optimises the parser for speed rather than
// for memory consumption, making the Parser faster from an execution
// time perspective, but yielding much more allocations, which in the
// long run could make the application slower due to GC pressure.
//
// Low memory mode is the default over a reader that implements
// io.Seeker, with or without a storage: contents are inflated from the
// pack again as the delta walk needs them, and the walk holds only the
// chain in flight. Some storage types do not support low memory mode
// (i.e. memory storage) and run in high memory mode regardless; this
// option asks for it over any storage or none.
//
// When enabled the inflated content of all delta objects (ofs and ref)
// will be loaded into cache, making it faster to navigate through them.
// If the reader provided to the parser does not implement io.Seeker,
// full objects are loaded into memory in either mode.
func WithHighMemoryMode() ParserOption {
	return func(p *Parser) {
		p.highMemoryMode = true
	}
}

// DefaultDeltaBaseCacheLimit is the budget of delta base contents the
// parser holds in memory in low memory mode, the same 96 MiB canonical
// git's core.deltaBaseCacheLimit defaults to; see
// WithDeltaBaseCacheLimit.
const DefaultDeltaBaseCacheLimit = 96 << 20

// WithDeltaBaseCacheLimit sets the budget, in bytes, of delta base
// contents the parser holds in memory in low memory mode while it
// resolves a pack's delta chains. A chain in flight past the budget
// has its contents held longest released and derived again as
// needed, so memory stays within the budget and one chain step
// whatever the pack's size or its chains' depth; a larger budget
// trades memory for fewer derivations, and a budget of zero or less
// holds nothing beyond the content in use.
func WithDeltaBaseCacheLimit(limit int64) ParserOption {
	return func(p *Parser) {
		p.heldLimit = limit
	}
}
