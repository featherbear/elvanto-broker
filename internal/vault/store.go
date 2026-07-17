package vault

import (
	"log"
	"time"
)

type backend interface {
	Close() error
	Set(Entry) error
	Get(string) (Entry, bool, error)
}

type Store struct {
	backend backend
}

type Entry struct {
	Sub          string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

func New(path, encryptionKey string) (*Store, error) {
	backend, err := newBackend(path)
	if err != nil {
		return nil, err
	}
	encrypted, err := newEncryptedBackend(backend, encryptionKey)
	if err != nil {
		backend.Close()
		return nil, err
	}
	return &Store{backend: encrypted}, nil
}

func (s *Store) Close() {
	if err := s.backend.Close(); err != nil {
		log.Printf("close token vault: %v", err)
	}
}

func (s *Store) Set(entry Entry) error {
	return s.backend.Set(entry)
}

func (s *Store) Get(sub string) (Entry, bool, error) {
	return s.backend.Get(sub)
}

func (e Entry) Expired() bool {
	if e.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(e.ExpiresAt.Add(-30 * time.Second))
}
