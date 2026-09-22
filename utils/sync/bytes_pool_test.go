package sync

import (
	"bytes"
	"testing"
)

// A buffer grown past maxPooledBuffer is not pooled: the next buffer
// handed out never carries that capacity.
func TestPutBytesBufferDropsLarge(t *testing.T) {
	big := bytes.NewBuffer(make([]byte, 0, maxPooledBuffer+1))
	PutBytesBuffer(big)
	for i := 0; i < 8; i++ {
		got := GetBytesBuffer()
		if got.Cap() > maxPooledBuffer {
			t.Fatalf("a buffer of capacity %d came out of the pool, over %d", got.Cap(), maxPooledBuffer)
		}
		PutBytesBuffer(got)
	}
	small := bytes.NewBuffer(make([]byte, 0, maxPooledBuffer))
	PutBytesBuffer(small)
}
