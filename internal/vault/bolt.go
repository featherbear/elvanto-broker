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

type boltStore struct {
	db *bolt.DB
}

func newBoltStore(path string) (*boltStore, error) {
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
	return &boltStore{db: db}, nil
}

func (s *boltStore) Close() error {
	return s.db.Close()
}

func (s *boltStore) Set(entry Entry) error {
	encoded, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode vault entry: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(entriesBucket).Put([]byte(entry.Sub), encoded)
	})
}

func (s *boltStore) Get(sub string) (Entry, bool, error) {
	var entry Entry
	err := s.db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket(entriesBucket).Get([]byte(sub))
		if value == nil {
			return nil
		}
		return json.Unmarshal(value, &entry)
	})
	if err != nil {
		return Entry{}, false, fmt.Errorf("read vault entry: %w", err)
	}
	return entry, entry.Sub != "", nil
}
