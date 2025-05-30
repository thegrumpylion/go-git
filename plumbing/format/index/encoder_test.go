package index

import (
	"bytes"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing"

	"github.com/google/go-cmp/cmp"
	. "gopkg.in/check.v1"
)

func (s *IndexSuite) TestEncode(c *C) {
	idx := &Index{
		Version: 2,
		Entries: []*Entry{{
			CreatedAt:  time.Now(),
			ModifiedAt: time.Now(),
			Dev:        4242,
			Inode:      424242,
			UID:        84,
			GID:        8484,
			Size:       42,
			Stage:      TheirMode,
			Hash:       plumbing.NewHash("e25b29c8946e0e192fae2edc1dabf7be71e8ecf3"),
			Name:       "foo",
		}, {
			CreatedAt:  time.Now(),
			ModifiedAt: time.Now(),
			Name:       "bar",
			Size:       82,
		}, {
			CreatedAt:  time.Now(),
			ModifiedAt: time.Now(),
			Name:       strings.Repeat(" ", 20),
			Size:       82,
		}},
	}

	buf := bytes.NewBuffer(nil)
	e := NewEncoder(buf)
	err := e.Encode(idx)
	c.Assert(err, IsNil)

	output := &Index{}
	d := NewDecoder(buf)
	err = d.Decode(output)
	c.Assert(err, IsNil)

	c.Assert(cmp.Equal(idx, output), Equals, true)

	c.Assert(output.Entries[0].Name, Equals, strings.Repeat(" ", 20))
	c.Assert(output.Entries[1].Name, Equals, "bar")
	c.Assert(output.Entries[2].Name, Equals, "foo")

}

func (s *IndexSuite) TestEncodeV4(c *C) {
	idx := &Index{
		Version: 4,
		Entries: []*Entry{{
			CreatedAt:  time.Now(),
			ModifiedAt: time.Now(),
			Dev:        4242,
			Inode:      424242,
			UID:        84,
			GID:        8484,
			Size:       42,
			Stage:      TheirMode,
			Hash:       plumbing.NewHash("e25b29c8946e0e192fae2edc1dabf7be71e8ecf3"),
			Name:       "foo",
		}, {
			CreatedAt:  time.Now(),
			ModifiedAt: time.Now(),
			Name:       "bar",
			Size:       82,
		}, {
			CreatedAt:  time.Now(),
			ModifiedAt: time.Now(),
			Name:       strings.Repeat(" ", 20),
			Size:       82,
		}, {
			CreatedAt:  time.Now(),
			ModifiedAt: time.Now(),
			Name:       "baz/bar",
			Size:       82,
		}, {
			CreatedAt:  time.Now(),
			ModifiedAt: time.Now(),
			Name:       "baz/bar/bar",
			Size:       82,
		}},
	}

	buf := bytes.NewBuffer(nil)
	e := NewEncoder(buf)
	err := e.Encode(idx)
	c.Assert(err, IsNil)

	output := &Index{}
	d := NewDecoder(buf)
	err = d.Decode(output)
	c.Assert(err, IsNil)

	c.Assert(cmp.Equal(idx, output), Equals, true)

	c.Assert(output.Entries[0].Name, Equals, strings.Repeat(" ", 20))
	c.Assert(output.Entries[1].Name, Equals, "bar")
	c.Assert(output.Entries[2].Name, Equals, "baz/bar")
	c.Assert(output.Entries[3].Name, Equals, "baz/bar/bar")
	c.Assert(output.Entries[4].Name, Equals, "foo")
}

func (s *IndexSuite) TestEncodeUnsupportedVersion(c *C) {
	idx := &Index{Version: 5}

	buf := bytes.NewBuffer(nil)
	e := NewEncoder(buf)
	err := e.Encode(idx)
	c.Assert(err, Equals, ErrUnsupportedVersion)
}

func (s *IndexSuite) TestEncodeWithIntentToAddUnsupportedVersion(c *C) {
	idx := &Index{
		Version: 3,
		Entries: []*Entry{{IntentToAdd: true}},
	}

	buf := bytes.NewBuffer(nil)
	e := NewEncoder(buf)
	err := e.Encode(idx)
	c.Assert(err, IsNil)

	output := &Index{}
	d := NewDecoder(buf)
	err = d.Decode(output)
	c.Assert(err, IsNil)

	c.Assert(cmp.Equal(idx, output), Equals, true)
	c.Assert(output.Entries[0].IntentToAdd, Equals, true)
}

func (s *IndexSuite) TestEncodeWithSkipWorktreeUnsupportedVersion(c *C) {
	idx := &Index{
		Version: 3,
		Entries: []*Entry{{SkipWorktree: true}},
	}

	buf := bytes.NewBuffer(nil)
	e := NewEncoder(buf)
	err := e.Encode(idx)
	c.Assert(err, IsNil)

	output := &Index{}
	d := NewDecoder(buf)
	err = d.Decode(output)
	c.Assert(err, IsNil)

	c.Assert(cmp.Equal(idx, output), Equals, true)
	c.Assert(output.Entries[0].SkipWorktree, Equals, true)
}
