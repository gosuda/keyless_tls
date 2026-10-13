// Package admission bounds concurrent work and per-identity request rates.
package admission

import (
	"sync"
	"time"
)

const idleRetention = time.Minute

type Limits struct {
	MaxConcurrent int
	MaxPerIdentity int
	MaxIdentities int
	RatePerSecond int
	Burst int
}

type identityState struct {
	active int
	tokens float64
	last time.Time
}

// Limiter is safe for concurrent use. Every successful TryAcquire must be
// paired with exactly one Release using the same identity.
type Limiter struct {
	mu sync.Mutex
	limits Limits
	active int
	identities map[string]*identityState
	rejected uint64
}

func New(limits Limits) *Limiter {
	if limits.MaxConcurrent <= 0 || limits.MaxPerIdentity <= 0 || limits.MaxIdentities <= 0 ||
		limits.RatePerSecond < 0 || (limits.RatePerSecond > 0 && limits.Burst <= 0) ||
		(limits.RatePerSecond == 0 && limits.Burst != 0) {
		panic("admission: invalid limits")
	}
	return &Limiter{
		limits: limits,
		identities: make(map[string]*identityState),
	}
}

// TryAcquire never waits. Rejected requests do not consume concurrency slots
// or rate tokens. Rate limits, when enabled, use a per-identity token bucket.
func (l *Limiter) TryAcquire(identity string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.active >= l.limits.MaxConcurrent {
		l.rejected++
		return false
	}

	now := time.Now()
	state := l.identities[identity]
	if state == nil {
		if len(l.identities) >= l.limits.MaxIdentities {
			for name, existing := range l.identities {
				if existing.active == 0 && now.Sub(existing.last) >= idleRetention {
					delete(l.identities, name)
				}
			}
		}
		if len(l.identities) >= l.limits.MaxIdentities {
			l.rejected++
			return false
		}
		state = &identityState{
			tokens: float64(l.limits.Burst),
			last: now,
		}
		l.identities[identity] = state
	}
	if state.active >= l.limits.MaxPerIdentity {
		l.rejected++
		return false
	}
	if l.limits.RatePerSecond > 0 {
		elapsed := now.Sub(state.last).Seconds()
		state.tokens += elapsed * float64(l.limits.RatePerSecond)
		if state.tokens > float64(l.limits.Burst) {
			state.tokens = float64(l.limits.Burst)
		}
		state.last = now
		if state.tokens < 1 {
			l.rejected++
			return false
		}
		state.tokens--
	}

	state.active++
	l.active++
	return true
}

func (l *Limiter) Release(identity string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	state := l.identities[identity]
	if state == nil || state.active == 0 {
		panic("admission: release without acquire")
	}
	state.active--
	l.active--
	if state.active == 0 && l.limits.RatePerSecond == 0 {
		delete(l.identities, identity)
	}
}

func (l *Limiter) Rejections() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rejected
}
