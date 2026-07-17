package vault

import (
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type postgresStore struct {
	db *sql.DB
}

func newPostgresStore(dsn string) (*postgresStore, error) {
	db, err := sql.Open("pgx", postgresDSN(dsn))
	if err != nil {
		return nil, fmt.Errorf("open postgres token vault: %w", err)
	}
	store := &postgresStore{db: db}
	if err := store.init(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *postgresStore) init() error {
	if err := s.db.Ping(); err != nil {
		return fmt.Errorf("connect postgres token vault: %w", err)
	}
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS token_vault_entries (
    sub text PRIMARY KEY,
    access_token text NOT NULL,
    refresh_token text NOT NULL DEFAULT '',
    expires_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
)`)
	if err != nil {
		return fmt.Errorf("initialize postgres token vault: %w", err)
	}
	return nil
}

func (s *postgresStore) Close() error {
	return s.db.Close()
}

func (s *postgresStore) Set(entry Entry) error {
	_, err := s.db.Exec(`
INSERT INTO token_vault_entries (
    sub,
    access_token,
    refresh_token,
    expires_at,
    updated_at
) VALUES ($1, $2, $3, $4, now())
ON CONFLICT (sub) DO UPDATE SET
    access_token = EXCLUDED.access_token,
    refresh_token = EXCLUDED.refresh_token,
    expires_at = EXCLUDED.expires_at,
    updated_at = now()`,
		entry.Sub,
		entry.AccessToken,
		entry.RefreshToken,
		postgresExpiresAt(entry),
	)
	if err != nil {
		return fmt.Errorf("store postgres token vault entry: %w", err)
	}
	return nil
}

func (s *postgresStore) Get(sub string) (Entry, bool, error) {
	var entry Entry
	var expiresAt sql.NullTime
	err := s.db.QueryRow(`
SELECT sub, access_token, refresh_token, expires_at
FROM token_vault_entries
WHERE sub = $1`, sub).Scan(
		&entry.Sub,
		&entry.AccessToken,
		&entry.RefreshToken,
		&expiresAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return Entry{}, false, nil
		}
		return Entry{}, false, fmt.Errorf("read postgres token vault entry: %w", err)
	}
	if expiresAt.Valid {
		entry.ExpiresAt = expiresAt.Time.Round(0).UTC()
	}
	return entry, entry.Sub != "", nil
}

func postgresExpiresAt(entry Entry) any {
	if entry.ExpiresAt.IsZero() {
		return nil
	}
	return entry.ExpiresAt.Round(0).UTC()
}
