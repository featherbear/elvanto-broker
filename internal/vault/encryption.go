package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const encryptedValuePrefix = "enc:v1:"

type encryptedBackend struct {
	next backend
	gcm  cipher.AEAD
}

func newEncryptedBackend(next backend, encodedKey string) (*encryptedBackend, error) {
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("decode TOKEN_VAULT_ENCRYPTION_KEY: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("TOKEN_VAULT_ENCRYPTION_KEY must decode to 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create vault cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create vault cipher mode: %w", err)
	}
	return &encryptedBackend{next: next, gcm: gcm}, nil
}

func (b *encryptedBackend) Close() error {
	return b.next.Close()
}

func (b *encryptedBackend) Set(entry Entry) error {
	encrypted, err := b.encryptEntry(entry)
	if err != nil {
		return err
	}
	return b.next.Set(encrypted)
}

func (b *encryptedBackend) Get(sub string) (Entry, bool, error) {
	entry, ok, err := b.next.Get(sub)
	if err != nil || !ok {
		return entry, ok, err
	}
	decrypted, err := b.decryptEntry(entry)
	if err != nil {
		return Entry{}, false, err
	}
	return decrypted, true, nil
}

func (b *encryptedBackend) encryptEntry(entry Entry) (Entry, error) {
	var err error
	entry.AccessToken, err = b.encryptValue(entry.AccessToken)
	if err != nil {
		return Entry{}, fmt.Errorf("encrypt access token: %w", err)
	}
	entry.RefreshToken, err = b.encryptValue(entry.RefreshToken)
	if err != nil {
		return Entry{}, fmt.Errorf("encrypt refresh token: %w", err)
	}
	return entry, nil
}

func (b *encryptedBackend) decryptEntry(entry Entry) (Entry, error) {
	var err error
	entry.AccessToken, err = b.decryptValue(entry.AccessToken)
	if err != nil {
		return Entry{}, fmt.Errorf("decrypt access token: %w", err)
	}
	entry.RefreshToken, err = b.decryptValue(entry.RefreshToken)
	if err != nil {
		return Entry{}, fmt.Errorf("decrypt refresh token: %w", err)
	}
	return entry, nil
}

func (b *encryptedBackend) encryptValue(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	nonce := make([]byte, b.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := b.gcm.Seal(nil, nonce, []byte(value), nil)
	payload := append(nonce, ciphertext...)
	return encryptedValuePrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func (b *encryptedBackend) decryptValue(value string) (string, error) {
	if value == "" || !strings.HasPrefix(value, encryptedValuePrefix) {
		return value, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, encryptedValuePrefix))
	if err != nil {
		return "", err
	}
	if len(payload) < b.gcm.NonceSize() {
		return "", fmt.Errorf("encrypted value is too short")
	}
	nonce := payload[:b.gcm.NonceSize()]
	ciphertext := payload[b.gcm.NonceSize():]
	plaintext, err := b.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
