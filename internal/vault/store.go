package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var entriesBucket = []byte("vault_entries")

type Store struct {
	db *bolt.DB
}

type Entry struct {
	Sub          string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	ClientID     string
	ClientSecret string
}

func New(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create vault db directory: %w", err)
		}
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open vault db: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(entriesBucket)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize vault db: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() {
	if err := s.db.Close(); err != nil {
		fmt.Printf("close vault db: %v\n", err)
	}
}

func (s *Store) Put(entry Entry) error {
	encoded, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode vault entry: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(entriesBucket).Put([]byte(entry.Sub), encoded)
	})
}

func (s *Store) BySubject(sub string) (Entry, bool) {
	var entry Entry
	err := s.db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket(entriesBucket).Get([]byte(sub))
		if value == nil {
			return nil
		}
		return json.Unmarshal(value, &entry)
	})
	return entry, err == nil && entry.Sub != ""
}

func (e Entry) Expired() bool {
	if e.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(e.ExpiresAt.Add(-30 * time.Second))
}
