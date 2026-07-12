package app

import (
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config contains all environment-backed settings required to run the broker.
type Config struct {
	// Addr is the TCP address the HTTP server listens on.
	Addr string `env:"ADDR" envDefault:":8080"`

	// Issuer is the public issuer URL advertised by the broker OAuth facade.
	Issuer string `env:"ISSUER" envDefault:"http://localhost:8080"`

	// TokenVaultDBPath is the bbolt database path used for cached Elvanto tokens.
	TokenVaultDBPath string `env:"TOKEN_VAULT_DB_PATH" envDefault:"elvanto-broker.db"`

	// ElvantoAuthURL is the upstream Elvanto OAuth authorization endpoint.
	ElvantoAuthURL string `env:"ELVANTO_AUTH_URL" envDefault:"https://api.elvanto.com/oauth"`

	// ElvantoTokenURL is the upstream Elvanto OAuth token endpoint.
	ElvantoTokenURL string `env:"ELVANTO_TOKEN_URL" envDefault:"https://api.elvanto.com/oauth/token"`

	// ElvantoAPIURL is the base URL for proxied Elvanto API requests.
	ElvantoAPIURL string `env:"ELVANTO_API_URL" envDefault:"https://api.elvanto.com/v1"`

	// ElvantoUserinfoURL is the Elvanto endpoint used to resolve the current user.
	ElvantoUserinfoURL string `env:"ELVANTO_USERINFO_URL" envDefault:"https://api.elvanto.com/v1/people/currentUser.json"`

	// BrokerTokenSigningSecret signs broker-issued JWT access and refresh tokens.
	BrokerTokenSigningSecret string `env:"BROKER_TOKEN_SIGNING_SECRET"`

	// BrokerAccessTokenTTL is the lifetime for broker-issued access tokens.
	BrokerAccessTokenTTL time.Duration `env:"BROKER_ACCESS_TOKEN_TTL" envDefault:"1h"`

	// BrokerRefreshTokenTTL is the lifetime for broker-issued refresh tokens.
	BrokerRefreshTokenTTL time.Duration `env:"BROKER_REFRESH_TOKEN_TTL" envDefault:"336h"`

	// IDPIssuer is the expected issuer claim for trusted IdP tokens.
	IDPIssuer string `env:"IDP_ISSUER"`

	// IDPJWKSURL is the JWKS endpoint for validating RS256 trusted IdP tokens.
	IDPJWKSURL string `env:"IDP_JWKS_URL"`

	// Audience is the expected audience claim for trusted IdP tokens.
	Audience string `env:"AUDIENCE"`

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
	return config, nil
}
