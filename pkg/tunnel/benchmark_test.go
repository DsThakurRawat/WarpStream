package tunnel

import (
	"bytes"
	"io"
	"sync"
	"testing"
)

// mockReadWriteCloser implements io.ReadWriteCloser for benchmarking purposes.
type mockReadWriteCloser struct {
	r   io.Reader
	w   io.Writer
	mtx sync.Mutex
}

func newMockReadWriteCloser(data []byte, discard bool) *mockReadWriteCloser {
	var w io.Writer
	if discard {
		w = io.Discard
	} else {
		w = new(bytes.Buffer)
	}
	return &mockReadWriteCloser{
		r: bytes.NewReader(data),
		w: w,
	}
}

func (m *mockReadWriteCloser) Read(p []byte) (n int, err error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return m.r.Read(p)
}

func (m *mockReadWriteCloser) Write(p []byte) (n int, err error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return m.w.Write(p)
}

func (m *mockReadWriteCloser) Close() error {
	return nil
}

func BenchmarkPipeBiDir(b *testing.B) {
	payload := make([]byte, 32*1024) // 32KB payload

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Create mock connections simulating two ends of a tunnel
		conn1 := newMockReadWriteCloser(payload, true)
		conn2 := newMockReadWriteCloser(payload, true)

		// This will copy data bi-directionally until EOF
		PipeBiDir(conn1, conn2)
	}
}
