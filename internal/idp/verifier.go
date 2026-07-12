package idp

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config controls validation of trusted IdP JWTs.
type Config struct {
	// Issuer is the expected issuer claim for trusted IdP tokens.
	Issuer string

	// JWKSURL is the JWKS endpoint used to validate RS256 tokens.
	JWKSURL string

	// Audience is the expected audience claim for trusted IdP tokens.
	Audience string

	// UserIDClaim is the claim used as the broker vault lookup subject.
	UserIDClaim string

	// AllowTokenInAPI allows trusted IdP tokens to authorize /api requests directly.
	AllowTokenInAPI bool
}

type Verifier struct {
	issuer          string
	jwksURL         string
	audience        string
	userIDClaim     string
	allowTokenInAPI bool

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

type claims map[string]any

type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Kid string   `json:"kid"`
	Alg string   `json:"alg"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5C []string `json:"x5c"`
}

func New(config Config) *Verifier {
	return &Verifier{
		issuer:          strings.TrimRight(config.Issuer, "/"),
		jwksURL:         config.JWKSURL,
		audience:        config.Audience,
		userIDClaim:     firstNonEmpty(config.UserIDClaim, "sub"),
		allowTokenInAPI: config.AllowTokenInAPI,
		keys:            map[string]*rsa.PublicKey{},
	}
}

func (v *Verifier) Configured() bool {
	return v != nil && v.issuer != "" && v.jwksURL != ""
}

func (v *Verifier) AllowTokenInAPI() bool {
	return v != nil && v.allowTokenInAPI
}

func (v *Verifier) Subject(ctx context.Context, token string) (string, error) {
	claims, err := v.verify(ctx, token)
	if err != nil {
		return "", err
	}
	subject := strings.TrimSpace(fmt.Sprint(claims[v.userIDClaim]))
	if subject == "" || subject == "<nil>" {
		return "", fmt.Errorf("IdP token missing %s claim", v.userIDClaim)
	}
	return subject, nil
}

func (v *Verifier) verify(ctx context.Context, token string) (claims, error) {
	if !v.Configured() {
		return nil, fmt.Errorf("IdP token validation is not configured")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid IdP token")
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeJWTPart(parts[0], &header); err != nil {
		return nil, fmt.Errorf("invalid IdP token header")
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported IdP token alg %q", header.Alg)
	}
	if err := v.verifySignature(ctx, header.Alg, header.Kid, parts); err != nil {
		return nil, fmt.Errorf("invalid IdP token signature")
	}

	var claims claims
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return nil, fmt.Errorf("invalid IdP token claims")
	}
	if err := v.validateClaims(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *Verifier) verifySignature(ctx context.Context, alg, kid string, parts []string) error {
	signed := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	key, err := v.key(ctx, kid)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(signed))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature)
}

func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if key := v.cachedKey(kid); key != nil {
		return key, nil
	}
	if err := v.fetchKeys(ctx); err != nil {
		return nil, err
	}
	if key := v.cachedKey(kid); key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("IdP signing key not found")
}

func (v *Verifier) cachedKey(kid string) *rsa.PublicKey {
	v.mu.Lock()
	defer v.mu.Unlock()
	if kid != "" {
		return v.keys[kid]
	}
	if len(v.keys) == 1 {
		for _, key := range v.keys {
			return key
		}
	}
	return nil
}

func (v *Verifier) fetchKeys(ctx context.Context) error {
	v.mu.Lock()
	if time.Since(v.fetchedAt) < 5*time.Minute && len(v.keys) > 0 {
		v.mu.Unlock()
		return nil
	}
	v.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create JWKS request")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("failed to fetch JWKS")
	}

	var payload jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return fmt.Errorf("invalid JWKS response")
	}
	keys := map[string]*rsa.PublicKey{}
	for _, raw := range payload.Keys {
		key, err := raw.publicKey()
		if err != nil || key == nil || raw.Kid == "" {
			continue
		}
		keys[raw.Kid] = key
	}
	if len(keys) == 0 {
		return fmt.Errorf("JWKS response did not contain RSA keys")
	}

	v.mu.Lock()
	v.keys = keys
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return nil
}

func (v *Verifier) validateClaims(claims claims) error {
	if issuer := strings.TrimRight(stringFromClaim(claims["iss"]), "/"); issuer != v.issuer {
		return fmt.Errorf("invalid IdP token issuer")
	}
	if exp := int64FromClaim(claims["exp"]); exp == 0 || time.Now().Unix() >= exp {
		return fmt.Errorf("expired IdP token")
	}
	if nbf := int64FromClaim(claims["nbf"]); nbf > 0 && time.Now().Unix() < nbf {
		return fmt.Errorf("IdP token is not active yet")
	}
	if v.audience != "" && !audienceMatches(claims["aud"], v.audience) {
		return fmt.Errorf("invalid IdP token audience")
	}
	return nil
}

func (j jwk) publicKey() (*rsa.PublicKey, error) {
	if len(j.X5C) > 0 {
		encoded, err := base64.StdEncoding.DecodeString(j.X5C[0])
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(encoded)
		if err != nil {
			return nil, err
		}
		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("certificate is not RSA")
		}
		return key, nil
	}
	if j.Kty != "RSA" || j.N == "" || j.E == "" {
		return nil, fmt.Errorf("JWK is not RSA")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func decodeJWTPart(part string, value any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(decoded, value)
}

func stringFromClaim(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func int64FromClaim(value any) int64 {
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case int64:
		return typed
	case int:
		return int64(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return parsed
	default:
		return 0
	}
}

func audienceMatches(value any, audience string) bool {
	switch typed := value.(type) {
	case string:
		return typed == audience
	case []any:
		for _, item := range typed {
			if fmt.Sprint(item) == audience {
				return true
			}
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
