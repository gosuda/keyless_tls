// Package admission bounds concurrent and per-identity work before expensive operations.
package admission

import (
	"sync"
	"sync/atomic"
	"time"
)

// Concurrency limits active work globally and per identity. Rejected work is
// never queued. Call Release once for each successful TryAcquire.
type Concurrency struct {
	mu       sync.Mutex
	maxTotal int
	maxPerID int
	active   int
	perID    map[string]int
	rejected atomic.Uint64
}

func NewConcurrency(maxTotal, maxPerID int) *Concurrency {
	if maxTotal <= 0 || maxPerID <= 0 {
		panic("admission: concurrency limits must be positive")
	}
	return &Concurrency{maxTotal: maxTotal, maxPerID: maxPerID}
}

func (l *Concurrency) TryAcquire(identity string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active >= l.maxTotal || l.perID[identity] >= l.maxPerID {
		l.rejected.Add(1)
		return false
	}
	if l.perID == nil {
		l.perID = make(map[string]int)
	}
	l.active++
	l.perID[identity]++
	return true
}

func (l *Concurrency) Release(identity string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perID[identity] == 0 {
		panic("admission: release without acquisition")
	}
	l.active--
	l.perID[identity]--
	if l.perID[identity] == 0 {
		delete(l.perID, identity)
	}
}

func (l *Concurrency) Rejected() uint64 {
	return l.rejected.Load()
}

// Buckets is a per-identity token bucket with bounded identity state. When
// full, the table evicts identities idle for a minute and rejects new ones
// if no idle entries exist. Call Allow before admitting work.
type Buckets struct {
	mu       sync.Mutex
	rate     float64
	burst    float64
	maxIDs   int
	perID    map[string]bucket
	rejected atomic.Uint64
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewBuckets(perSecond, burst, maxIDs int) *Buckets {
	if perSecond <= 0 || burst <= 0 || maxIDs <= 0 {
		panic("admission: bucket limits must be positive")
	}
	return &Buckets{
		rate:   float64(perSecond),
		burst:  float64(burst),
		maxIDs: maxIDs,
		perID:  make(map[string]bucket),
	}
}

func (l *Buckets) Allow(identity string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, exists := l.perID[identity]
	if !exists {
		if len(l.perID) >= l.maxIDs {
			for key, entry := range l.perID {
				if now.Sub(entry.last) >= time.Minute {
					delete(l.perID, key)
				}
			}
			if len(l.perID) >= l.maxIDs {
				l.rejected.Add(1)
				return false
			}
		}
		b = bucket{tokens: l.burst, last: now}
	}

	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(l.burst, b.tokens+elapsed*l.rate)
	}
	b.last = now
	if b.tokens < 1 {
		l.perID[identity] = b
		l.rejected.Add(1)
		return false
	}
	b.tokens--
	l.perID[identity] = b
	return true
}

func (l *Buckets) Rejected() uint64 {
	return l.rejected.Load()
}
