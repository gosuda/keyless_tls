package signer

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"sync"
)

type KeyStore interface {
	Signer(ctx context.Context, keyID string) (crypto.Signer, error)
}

type StaticKeyStore struct {
	mu      sync.RWMutex
	signers map[string]crypto.Signer
}

func NewStaticKeyStore() *StaticKeyStore {
	return &StaticKeyStore{signers: make(map[string]crypto.Signer)}
}

func (s *StaticKeyStore) Put(keyID string, signer crypto.Signer) error {
	if keyID == "" {
		return errors.New("key id is required")
	}
	if signer == nil {
		return errors.New("signer is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signers[keyID] = signer
	return nil
}

func (s *StaticKeyStore) Signer(_ context.Context, keyID string) (crypto.Signer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	signer, ok := s.signers[keyID]
	if !ok {
		return nil, fmt.Errorf("unknown key id: %s", keyID)
	}
	return signer, nil
}
