package vault

import "strings"

func newBackend(path string) (backend, error) {
	if isPostgresDSN(path) {
		return newPostgresStore(path)
	}
	return newBoltStore(path)
}

func isPostgresDSN(value string) bool {
	return strings.HasPrefix(value, "sql://") || strings.HasPrefix(value, "postgres://") || strings.HasPrefix(value, "postgresql://")
}

func postgresDSN(value string) string {
	if strings.HasPrefix(value, "sql://") {
		return "postgres://" + strings.TrimPrefix(value, "sql://")
	}
	return value
}
