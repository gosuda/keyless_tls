package admission

import (
	"sync"
	"testing"
)

func TestConcurrentAndPerIdentityLimits(t *testing.T) {
	limiter := New(Limits{MaxConcurrent: 2, MaxPerIdentity: 1, MaxIdentities: 2})
	if !limiter.TryAcquire("a") {
		t.Fatal("first identity was rejected")
	}
	if limiter.TryAcquire("a") {
		t.Fatal("same identity exceeded its concurrency limit")
	}
	if !limiter.TryAcquire("b") {
		t.Fatal("second identity was rejected")
	}
	if limiter.TryAcquire("c") {
		t.Fatal("global concurrency limit was bypassed")
	}
	limiter.Release("a")
	if !limiter.TryAcquire("c") {
		t.Fatal("released slot was not reusable")
	}
	limiter.Release("b")
	limiter.Release("c")
	if got := limiter.Rejections(); got != 2 {
		t.Fatalf("rejections = %d, want 2", got)
	}
}

func TestTokenBucketsAndBoundedIdentities(t *testing.T) {
	limiter := New(Limits{
		MaxConcurrent: 2, MaxPerIdentity: 2, MaxIdentities: 2,
		RatePerSecond: 1, Burst: 1,
	})
	if !limiter.TryAcquire("a") {
		t.Fatal("first token was rejected")
	}
	limiter.Release("a")
	if limiter.TryAcquire("a") {
		t.Fatal("second immediate request exceeded token bucket")
	}
	if !limiter.TryAcquire("b") {
		t.Fatal("independent identity should have its own bucket")
	}
	limiter.Release("b")
	if limiter.TryAcquire("c") {
		t.Fatal("identity registry exceeded its bound")
	}
	if got := limiter.Rejections(); got != 2 {
		t.Fatalf("rejections = %d, want 2", got)
	}
}

func TestLimiterParallelFlood(t *testing.T) {
	limiter := New(Limits{MaxConcurrent: 3, MaxPerIdentity: 3, MaxIdentities: 3})
	const workers = 64
	start := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	var accepted sync.WaitGroup
	accepted.Add(workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok := limiter.TryAcquire("shared")
			accepted.Done()
			if !ok {
				return
			}
			<-release
			limiter.Release("shared")
		}()
	}
	close(start)
	accepted.Wait()
	if got := limiter.Rejections(); got != workers-3 {
		t.Fatalf("rejections = %d, want %d", got, workers-3)
	}
	close(release)
	wg.Wait()
	if !limiter.TryAcquire("shared") {
		t.Fatal("all slots should be returned after flood")
	}
	limiter.Release("shared")
}
