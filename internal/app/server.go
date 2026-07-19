package app

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"elvanto-broker/internal/elvanto"
	"elvanto-broker/internal/httpx"
	"elvanto-broker/internal/idp"
	"elvanto-broker/internal/tokens"
	"elvanto-broker/internal/vault"
)

type Server struct {
	config           Config
	elvanto          *elvanto.Client
	vault            *vault.Store
	tokens           *tokens.Service
	idp              *idp.Verifier
	cors             *httpx.CORS
	elvantoSubHeader string
}

func NewFromEnv() (*Server, error) {
	config, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	return New(config)
}

func New(config Config) (*Server, error) {
	store, err := vault.New(config.TokenVaultDBPath, config.TokenVaultEncryptionKey)
	if err != nil {
		return nil, err
	}
	tokenService, err := tokens.New(tokens.Config{
		Secret:     []byte(config.BrokerTokenSigningSecret),
		AccessTTL:  config.BrokerAccessTokenTTL,
		RefreshTTL: config.BrokerRefreshTokenTTL,
	})
	if err != nil {
		store.Close()
		return nil, err
	}

	return &Server{
		config: config,
		elvanto: elvanto.New(elvanto.Config{
			AuthURL:     config.ElvantoAuthURL,
			TokenURL:    config.ElvantoTokenURL,
			APIURL:      config.ElvantoAPIURL,
			UserinfoURL: config.ElvantoUserinfoURL,
		}),
		vault:  store,
		tokens: tokenService,
		idp: idp.New(idp.Config{
			Issuer:          config.IDPExpectedIssuer,
			JWKSURL:         config.IDPJWKSURL,
			Audience:        config.IDPExpectedAudience,
			UserIDClaim:     config.IDPUserIDClaim,
			AllowTokenInAPI: config.AllowIDPTokenInAPI,
		}),
		cors:             httpx.NewCORS(config.CORSAllowedOrigins),
		elvantoSubHeader: config.ElvantoSubHeader,
	}, nil
}

func (s *Server) Run() error {
	defer s.vault.Close()

	s.logStartup()
	mainErr := make(chan error, 1)
	go func() {
		mainErr <- http.ListenAndServe(s.config.ServerListenAddress, httpx.LogRequests(s.routes()))
	}()
	if s.config.TokenIssuerListenAddress == "" {
		return <-mainErr
	}

	issueServer := &http.Server{
		Addr:    s.config.TokenIssuerListenAddress,
		Handler: httpx.LogRequests(s.tokenIssueRoutes()),
	}
	issueErr := make(chan error, 1)
	go func() {
		log.Printf("Elvanto broker token issue server listening on %s", s.config.TokenIssuerListenAddress)
		issueErr <- issueServer.ListenAndServe()
	}()

	select {
	case err := <-issueErr:
		if errors.Is(err, http.ErrServerClosed) {
			return <-mainErr
		}
		return err
	case err := <-mainErr:
		if errors.Is(err, http.ErrServerClosed) {
			return <-issueErr
		}
		return err
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("The Elvanto broker is running\n"))
	})

	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.Handle("/oidc/", http.StripPrefix("/oidc", s.oidcRoutes()))

	mux.HandleFunc("POST /token/exchange", s.exchangeToken)
	mux.HandleFunc("OPTIONS /token/exchange", s.exchangeToken)

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api", s.api)
	mux.HandleFunc("/api/", s.api)

	return mux
}

func (s *Server) tokenIssueRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /token/issue", s.issueToken)
	mux.HandleFunc("POST /token/issue", s.issueToken)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return mux
}

func (s *Server) logStartup() {
	log.Printf("Elvanto broker starting")
	log.Printf("public listener: %s", s.config.ServerListenAddress)
	log.Printf("issuer: %s", s.config.Issuer)
	log.Printf("upstream Elvanto API: %s", s.config.ElvantoAPIURL)
	log.Printf("token vault backend: %s", tokenVaultBackend(s.config.TokenVaultDBPath))
	log.Printf("broker OIDC clients configured: %d", len(s.config.BrokerOIDCAllowedClients))
	log.Printf("broker access token TTL: %s", s.config.BrokerAccessTokenTTL)
	log.Printf("broker refresh token TTL: %s", s.config.BrokerRefreshTokenTTL)
	log.Printf("broker token signing secret configured: %t", s.config.BrokerTokenSigningSecret != "")

	if s.idp.Configured() {
		log.Printf("IdP token validation: enabled issuer=%s audience_configured=%t user_id_claim=%s", s.config.IDPExpectedIssuer, s.config.IDPExpectedAudience != "", s.config.IDPUserIDClaim)
	} else {
		log.Printf("IdP token validation: disabled")
	}
	log.Printf("IdP tokens accepted by /api/*: %t", s.config.AllowIDPTokenInAPI)

	if len(s.config.CORSAllowedOrigins) == 0 {
		log.Printf("CORS allowed origins: all")
	} else {
		log.Printf("CORS allowed origins: %s", strings.Join(s.config.CORSAllowedOrigins, ","))
	}

	if s.config.TokenIssuerListenAddress == "" {
		log.Printf("internal token issue endpoint: disabled")
	} else {
		log.Printf("internal token issue listener: %s", s.config.TokenIssuerListenAddress)
		log.Printf("internal token issue subject header configured: %t", s.config.ElvantoSubHeader != "")
	}
}

func tokenVaultBackend(path string) string {
	if strings.HasPrefix(path, "sql://") || strings.HasPrefix(path, "postgres://") || strings.HasPrefix(path, "postgresql://") {
		return "postgres"
	}
	return "bbolt"
}

func (s *Server) apiTargetURL(requestURL *url.URL) (string, error) {
	target, err := url.Parse(strings.TrimRight(s.elvanto.APIURL(), "/"))
	if err != nil {
		return "", err
	}
	suffix := strings.TrimPrefix(requestURL.Path, "/api")
	target.Path = strings.TrimRight(target.Path, "/") + "/" + strings.TrimLeft(suffix, "/")
	target.RawQuery = requestURL.RawQuery
	return target.String(), nil
}
