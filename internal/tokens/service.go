package tokens

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"elvanto-broker/internal/httpx"
)

const issuer = "elvanto-broker"

// Config controls broker-issued JWT signing and lifetimes.
type Config struct {
	// Secret signs broker-issued JWTs.
	Secret []byte

	// AccessTTL is the lifetime for broker-issued access tokens.
	AccessTTL time.Duration

	// RefreshTTL is the lifetime for broker-issued refresh tokens.
	RefreshTTL time.Duration
}

type Service struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

type claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func New(config Config) (*Service, error) {
	secret := config.Secret
	if len(secret) == 0 {
		generated, err := httpx.RandomToken(32)
		if err != nil {
			return nil, err
		}
		secret = []byte(generated)
	}
	return &Service{
		secret:     secret,
		accessTTL:  config.AccessTTL,
		refreshTTL: config.RefreshTTL,
	}, nil
}

func (s *Service) AccessTTL() time.Duration {
	return s.accessTTL
}

func (s *Service) IssueAccess(sub string) (string, error) {
	return s.issue(sub, "access", s.accessTTL)
}

func (s *Service) IssueRefresh(sub string) (string, error) {
	return s.issue(sub, "refresh", s.refreshTTL)
}

func (s *Service) AccessSubject(token string) (string, error) {
	return s.subject(token, "access")
}

func (s *Service) RefreshSubject(token string) (string, error) {
	return s.subject(token, "refresh")
}

func (s *Service) issue(sub, audience string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := claims{
		Issuer:    issuer,
		Subject:   sub,
		Audience:  audience,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}

	header, err := encodeJWTPart(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := encodeJWTPart(claims)
	if err != nil {
		return "", err
	}
	signed := header + "." + payload
	return signed + "." + signJWT(signed, s.secret), nil
}

func (s *Service) subject(token, audience string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid broker token")
	}
	signed := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(parts[2]), []byte(signJWT(signed, s.secret))) {
		return "", fmt.Errorf("invalid broker token")
	}

	var claims claims
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return "", fmt.Errorf("invalid broker token")
	}
	if claims.Issuer != issuer || claims.Subject == "" || claims.Audience != audience {
		return "", fmt.Errorf("invalid broker token")
	}
	if time.Now().Unix() >= claims.ExpiresAt {
		return "", fmt.Errorf("expired broker token")
	}
	return claims.Subject, nil
}

func encodeJWTPart(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeJWTPart(part string, value any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(decoded, value)
}

func signJWT(value string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
