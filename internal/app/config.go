package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config contains all environment-backed settings required to run the broker.
type Config struct {
	// ServerListenAddress is the TCP address the public HTTP server listens on.
	ServerListenAddress string `env:"SERVER_LISTEN_ADDRESS" envDefault:":8080"`

	// TokenIssuerListenAddress is the optional TCP address the internal token issue server listens on.
	TokenIssuerListenAddress string `env:"TOKEN_ISSUER_LISTEN_ADDRESS"`

	// Issuer is the public issuer URL advertised by the broker OAuth facade.
	Issuer string `env:"ISSUER" envDefault:"http://localhost:8080"`

	// TokenVaultDBPath is a bbolt file path or sql:// Postgres DSN for cached Elvanto tokens.
	TokenVaultDBPath string `env:"TOKEN_VAULT_DB_PATH" envDefault:"elvanto-broker.db"`

	// TokenVaultEncryptionKey is a base64-encoded 32-byte AES-GCM key for vault secrets.
	TokenVaultEncryptionKey string `env:"TOKEN_VAULT_ENCRYPTION_KEY,required"`

	// ElvantoAuthURL is the upstream Elvanto OAuth authorization endpoint.
	ElvantoAuthURL string `env:"ELVANTO_AUTH_URL" envDefault:"https://api.elvanto.com/oauth"`

	// ElvantoTokenURL is the upstream Elvanto OAuth token endpoint.
	ElvantoTokenURL string `env:"ELVANTO_TOKEN_URL" envDefault:"https://api.elvanto.com/oauth/token"`

	// ElvantoAPIURL is the base URL for proxied Elvanto API requests.
	ElvantoAPIURL string `env:"ELVANTO_API_URL" envDefault:"https://api.elvanto.com/v1"`

	// ElvantoUserinfoURL is the Elvanto endpoint used to resolve the current user.
	ElvantoUserinfoURL string `env:"ELVANTO_USERINFO_URL" envDefault:"https://api.elvanto.com/v1/people/currentUser.json"`

	// ElvantoClientID is the global Elvanto OAuth client ID used by the broker.
	ElvantoClientID string `env:"ELVANTO_CLIENT_ID,required"`

	// ElvantoClientSecret is the global Elvanto OAuth client secret used by the broker.
	ElvantoClientSecret string `env:"ELVANTO_CLIENT_SECRET,required"`

	// BrokerOIDCAllowedClientsRaw is the comma-separated client_id:client_secret allowlist for the broker OIDC facade.
	BrokerOIDCAllowedClientsRaw string `env:"BROKER_OIDC_ALLOWED_CLIENTS,required"`

	// BrokerOIDCAllowedClients maps broker OIDC client IDs to their allowed client secrets.
	BrokerOIDCAllowedClients map[string]string `env:"-"`

	// BrokerTokenSigningSecret signs broker-issued JWT access and refresh tokens.
	BrokerTokenSigningSecret string `env:"BROKER_TOKEN_SIGNING_SECRET"`

	// BrokerAccessTokenTTL is the lifetime for broker-issued access tokens.
	BrokerAccessTokenTTL time.Duration `env:"BROKER_ACCESS_TOKEN_TTL" envDefault:"1h"`

	// BrokerRefreshTokenTTL is the lifetime for broker-issued refresh tokens.
	BrokerRefreshTokenTTL time.Duration `env:"BROKER_REFRESH_TOKEN_TTL" envDefault:"336h"`

	// IDPExpectedIssuer is the expected issuer claim for trusted IdP tokens.
	IDPExpectedIssuer string `env:"IDP_EXPECTED_ISSUER"`

	// IDPJWKSURL is the JWKS endpoint for validating RS256 trusted IdP tokens.
	IDPJWKSURL string `env:"IDP_JWKS_URL"`

	// IDPExpectedAudience is the expected audience claim for trusted IdP tokens.
	IDPExpectedAudience string `env:"IDP_EXPECTED_AUDIENCE"`

	// UserIDClaim is the trusted IdP claim containing the Elvanto person ID.
	IDPUserIDClaim string `env:"IDP_USER_ID_CLAIM" envDefault:"sub"`

	// AllowIDPTokenInAPI allows trusted IdP tokens to call /api directly.
	AllowIDPTokenInAPI bool `env:"ALLOW_IDP_TOKEN_IN_API" envDefault:"false"`

	// CORSAllowedOrigins restricts browser origins for CORS-enabled endpoints.
	CORSAllowedOrigins []string `env:"CORS_ALLOWS_ORIGINS" envSeparator:","`

	// ElvantoSubHeader is the trusted request header used by /token/issue.
	ElvantoSubHeader string `env:"ELVANTO_SUB_HEADER"`
}

func LoadConfig() (Config, error) {
	var config Config
	if err := env.Parse(&config); err != nil {
		return Config{}, err
	}
	config.Issuer = strings.TrimRight(config.Issuer, "/")
	allowedClients, err := parseBrokerOIDCAllowedClients(config.BrokerOIDCAllowedClientsRaw)
	if err != nil {
		return Config{}, err
	}
	config.BrokerOIDCAllowedClients = allowedClients
	return config, nil
}

func parseBrokerOIDCAllowedClients(value string) (map[string]string, error) {
	clients := map[string]string{}
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		clientID, clientSecret, ok := strings.Cut(entry, ":")
		clientID = strings.TrimSpace(clientID)
		clientSecret = strings.TrimSpace(clientSecret)
		if !ok || clientID == "" || clientSecret == "" {
			return nil, fmt.Errorf("BROKER_OIDC_ALLOWED_CLIENTS must be comma-separated client_id:client_secret pairs")
		}
		if _, exists := clients[clientID]; exists {
			return nil, fmt.Errorf("BROKER_OIDC_ALLOWED_CLIENTS contains duplicate client_id %q", clientID)
		}
		clients[clientID] = clientSecret
	}
	return clients, nil
}
