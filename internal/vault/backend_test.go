package vault

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

const testEncryptionKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

func TestPostgresDSN(t *testing.T) {
	tests := map[string]string{
		"sql://user:pass@host:5432/db":        "postgres://user:pass@host:5432/db",
		"postgres://user:pass@host:5432/db":   "postgres://user:pass@host:5432/db",
		"postgresql://user:pass@host:5432/db": "postgresql://user:pass@host:5432/db",
	}

	for input, expected := range tests {
		if actual := postgresDSN(input); actual != expected {
			t.Fatalf("postgresDSN(%q) = %q, expected %q", input, actual, expected)
		}
	}
}

func TestIsPostgresDSN(t *testing.T) {
	for _, value := range []string{
		"sql://user:pass@host:5432/db",
		"postgres://user:pass@host:5432/db",
		"postgresql://user:pass@host:5432/db",
	} {
		if !isPostgresDSN(value) {
			t.Fatalf("expected %q to be detected as Postgres DSN", value)
		}
	}

	if isPostgresDSN("/data/elvanto-broker.db") {
		t.Fatal("file path should not be detected as Postgres DSN")
	}
}

func TestBoltStoreSetAndGet(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "vault.db"), testEncryptionKey)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer store.Close()

	expiresAt := time.Now().Add(time.Hour).Round(0).UTC()
	entry := Entry{
		Sub:          "person-123",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    expiresAt,
	}
	if err := store.Set(entry); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	actual, ok, err := store.Get(entry.Sub)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !ok {
		t.Fatal("Get() did not find entry")
	}
	if actual.Sub != entry.Sub || actual.AccessToken != entry.AccessToken || actual.RefreshToken != entry.RefreshToken {
		t.Fatalf("Get() = %+v, expected %+v", actual, entry)
	}
	if !actual.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("ExpiresAt = %s, expected %s", actual.ExpiresAt, expiresAt)
	}
}

func TestBoltStoreEncryptsSecretFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	store, err := New(path, testEncryptionKey)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	entry := Entry{
		Sub:          "person-123",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
	}
	if err := store.Set(entry); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	store.Close()

	var stored Entry
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("open bbolt db: %v", err)
	}
	defer db.Close()
	if err := db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket(entriesBucket).Get([]byte(entry.Sub))
		return json.Unmarshal(value, &stored)
	}); err != nil {
		t.Fatalf("read raw entry: %v", err)
	}

	for name, value := range map[string]string{
		"access token":  stored.AccessToken,
		"refresh token": stored.RefreshToken,
	} {
		if value == "" || value == entry.AccessToken || value == entry.RefreshToken {
			t.Fatalf("%s was not encrypted: %q", name, value)
		}
		if value[:len(encryptedValuePrefix)] != encryptedValuePrefix {
			t.Fatalf("%s missing encrypted prefix: %q", name, value)
		}
	}
}

func TestVaultReadsExistingPlaintextEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	store, err := New(path, testEncryptionKey)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	store.Close()

	entry := Entry{
		Sub:          "person-123",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}

	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("open bbolt db: %v", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(entriesBucket).Put([]byte(entry.Sub), encoded)
	}); err != nil {
		t.Fatalf("write raw entry: %v", err)
	}
	db.Close()

	store, err = New(path, testEncryptionKey)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer store.Close()
	actual, ok, err := store.Get(entry.Sub)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !ok {
		t.Fatal("Get() did not find entry")
	}
	if actual.AccessToken != entry.AccessToken || actual.RefreshToken != entry.RefreshToken {
		t.Fatalf("Get() = %+v, expected %+v", actual, entry)
	}
}
