package tunnel

import (
	"bytes"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

type dummyRWC struct {
	io.Reader
	io.Writer
	closed atomic.Bool
}

func (d *dummyRWC) Close() error {
	d.closed.Store(true)
	return nil
}

func TestIdleTimeoutConn_ClosesOnIdle(t *testing.T) {
	dummy := &dummyRWC{
		Reader: bytes.NewReader([]byte("test")),
		Writer: new(bytes.Buffer),
	}

	ic := NewIdleTimeoutConn(dummy, 50*time.Millisecond)
	time.Sleep(120 * time.Millisecond)

	if !dummy.closed.Load() {
		t.Errorf("expected underlying connection to be closed after idle timeout")
	}
	_ = ic.Close()
}

func TestIdleTimeoutConn_ActivityResetsTimer(t *testing.T) {
	dummy := &dummyRWC{
		Reader: bytes.NewReader([]byte("test")),
		Writer: new(bytes.Buffer),
	}

	ic := NewIdleTimeoutConn(dummy, 80*time.Millisecond)
	for i := 0; i < 3; i++ {
		time.Sleep(40 * time.Millisecond)
		_, _ = ic.Write([]byte("a"))
	}

	if dummy.closed.Load() {
		t.Errorf("expected connection to remain open during activity")
	}

	_ = ic.Close()
}
