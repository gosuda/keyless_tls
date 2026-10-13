package admission

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrencyGlobalAndPerIdentity(t *testing.T) {
	limit := NewConcurrency(2, 1)
	if !limit.TryAcquire("a") || !limit.TryAcquire("b") {
		t.Fatal("expected available slots")
	}
	if limit.TryAcquire("a") || limit.TryAcquire("c") {
		t.Fatal("expected per-identity and global rejection")
	}
	limit.Release("a")
	if !limit.TryAcquire("c") {
		t.Fatal("released capacity was not reusable")
	}
	limit.Release("b")
	limit.Release("c")
	if limit.Rejected() != 2 {
		t.Fatalf("rejections = %d, want 2", limit.Rejected())
	}
}

func TestConcurrencyParallelFlood(t *testing.T) {
	const max = 4
	limit := NewConcurrency(max, max)
	var active atomic.Int32
	var peak atomic.Int32
	var wg sync.WaitGroup
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !limit.TryAcquire("shared") {
				return
			}
			defer limit.Release("shared")
			n := active.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			active.Add(-1)
		}()
	}
	wg.Wait()
	if got := peak.Load(); got > max {
		t.Fatalf("peak concurrent work = %d, want <= %d", got, max)
	}
	if limit.Rejected() == 0 {
		t.Fatal("expected overload rejections")
	}
}

func TestBucketsRateAndCapacity(t *testing.T) {
	limit := NewBuckets(1, 2, 2)
	now := time.Unix(100, 0)
	if !limit.Allow("a", now) || !limit.Allow("a", now) {
		t.Fatal("expected initial burst")
	}
	if limit.Allow("a", now) {
		t.Fatal("expected exhausted bucket")
	}
	if !limit.Allow("a", now.Add(time.Second)) {
		t.Fatal("expected refill")
	}
	if !limit.Allow("b", now) || limit.Allow("c", now) {
		t.Fatal("expected bounded identity state")
	}
	if !limit.Allow("c", now.Add(2*time.Minute)) {
		t.Fatal("expected eviction of idle identity")
	}
	if got := limit.Rejected(); got != 2 {
		t.Fatalf("rejections = %d, want 2", got)
	}
}
