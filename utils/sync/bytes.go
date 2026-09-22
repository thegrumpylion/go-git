package sync

import (
	"bytes"
	"sync"
)

var (
	size = 32 * 1024

	byteSlice = sync.Pool{
		New: func() any {
			b := make([]byte, size)
			return &b
		},
	}
	bytesBuffer = sync.Pool{
		New: func() any {
			return bytes.NewBuffer(nil)
		},
	}
)

// GetByteSlice returns a *[]byte that is managed by a sync.Pool.
// The initial slice length will be 32768 (32kb).
//
// After use, the *[]byte should be put back into the sync.Pool
// by calling PutByteSlice.
func GetByteSlice() *[]byte {
	buf := byteSlice.Get().(*[]byte)
	b := *buf
	if len(b) < size {
		b = b[:cap(b)]
	}

	clear(b)
	return &b
}

// PutByteSlice puts buf back into its sync.Pool.
func PutByteSlice(buf *[]byte) {
	if buf == nil {
		return
	}

	byteSlice.Put(buf)
}

// GetBytesBuffer returns a *bytes.Buffer that is managed by a sync.Pool.
// Returns a buffer that is reset and ready for use.
//
// After use, the *bytes.Buffer should be put back into the sync.Pool
// by calling PutBytesBuffer.
func GetBytesBuffer() *bytes.Buffer {
	buf := bytesBuffer.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

// maxPooledBuffer is the largest capacity a buffer is pooled at: one
// grown past it is left to the collector, as a pool of buffers the
// size of the largest objects they ever held is a working set the
// collector counts as live — go's fmt draws the same line for its own
// buffers.
const maxPooledBuffer = 256 << 10

// PutBytesBuffer puts buf back into its sync.Pool, unless it grew
// past maxPooledBuffer.
func PutBytesBuffer(buf *bytes.Buffer) {
	if buf == nil || buf.Cap() > maxPooledBuffer {
		return
	}
	bytesBuffer.Put(buf)
}
