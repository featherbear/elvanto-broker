package app

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"elvanto-broker/internal/elvanto"
	"elvanto-broker/internal/httpx"
	"elvanto-broker/internal/vault"
)

func (s *Server) oidcRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", s.auth)
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("GET /userinfo", s.userinfo)
	return mux
}

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.config.Issuer,
		"authorization_endpoint":                s.config.Issuer + "/oidc/auth",
		"token_endpoint":                        s.config.Issuer + "/oidc/token",
		"userinfo_endpoint":                     s.config.Issuer + "/oidc/userinfo",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		"scopes_supported":                      elvanto.SupportedScopes(),
	})
}

func (s *Server) auth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "only response_type=code is supported")
		return
	}

	redirectURI := q.Get("redirect_uri")
	if q.Get("client_id") == "" || redirectURI == "" {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid client_id or redirect_uri")
		return
	}
	if q.Get("client_id") != s.config.BrokerOIDCClientID {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "unauthorized_client", "invalid client_id")
		return
	}
	if _, err := url.ParseRequestURI(redirectURI); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri must be an absolute URL")
		return
	}
	scopes := strings.Fields(q.Get("scope"))

	if validScopes, err := elvanto.ValidateScopes(scopes); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	} else {
		scopes = validScopes
	}

	location, err := url.Parse(s.elvanto.AuthURL())
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "invalid Elvanto authorization URL")
		return
	}
	values := url.Values{}
	values.Set("type", "web_server")
	values.Set("client_id", s.config.ElvantoClientID)
	values.Set("redirect_uri", redirectURI)

	if len(scopes) > 0 {
		values.Set("scope", strings.Join(scopes, ","))
	} else {
		values.Set("scope", "ManagePeople")
	}

	if state := q.Get("state"); state != "" {
		values.Set("state", state)
	}
	location.RawQuery = values.Encode()

	http.Redirect(w, r, location.String(), http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	if clientID, clientSecret, ok := r.BasicAuth(); ok {
		if r.Form.Get("client_id") == "" {
			r.Form.Set("client_id", clientID)
		}
		if r.Form.Get("client_secret") == "" {
			r.Form.Set("client_secret", clientSecret)
		}
	}
	if !s.validBrokerClient(r.Form.Get("client_id"), r.Form.Get("client_secret")) {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}
	if r.Form.Get("grant_type") == "refresh_token" {
		s.refreshBrokerToken(w, r)
		return
	}

	form, err := s.elvantoTokenForm(r.Form)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	token, err := s.elvanto.ExchangeToken(r.Context(), form)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusBadGateway, "server_error", err.Error())
		return
	}
	entry, err := s.cacheTokenResponse(r.Context(), token, r.Form.Get("refresh_token"))
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusBadGateway, "server_error", err.Error())
		return
	}
	brokerToken, err := s.tokens.IssueAccess(entry.Sub)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue broker token")
		return
	}
	brokerRefreshToken, err := s.tokens.IssueRefresh(entry.Sub)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue broker refresh token")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, s.brokerTokenResponse(token, brokerToken, brokerRefreshToken))
}

func (s *Server) refreshBrokerToken(w http.ResponseWriter, r *http.Request) {
	brokerRefreshToken := r.Form.Get("refresh_token")
	if brokerRefreshToken == "" {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	sub, err := s.tokens.RefreshSubject(brokerRefreshToken)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}
	entry, ok, err := s.vault.Get(sub)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to read token vault")
		return
	}
	if !ok {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", "invalid broker refresh token")
		return
	}

	token, entry, err := s.refreshVaultEntryToken(r.Context(), entry)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}
	brokerToken, err := s.tokens.IssueAccess(entry.Sub)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue broker token")
		return
	}
	newBrokerRefreshToken, err := s.tokens.IssueRefresh(entry.Sub)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue broker refresh token")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, s.brokerTokenResponse(token, brokerToken, newBrokerRefreshToken))
}

func (s *Server) validBrokerClient(clientID, clientSecret string) bool {
	return clientID == s.config.BrokerOIDCClientID && clientSecret == s.config.BrokerOIDCClientSecret
}

func (s *Server) elvantoTokenForm(input url.Values) (url.Values, error) {
	grantType := input.Get("grant_type")
	if grantType != "authorization_code" && grantType != "refresh_token" {
		return nil, fmt.Errorf("only authorization_code and refresh_token are supported")
	}

	requiredFields := []string{}
	if grantType == "authorization_code" {
		requiredFields = append(requiredFields, "code", "redirect_uri")
	} else {
		requiredFields = append(requiredFields, "refresh_token")
	}
	for _, field := range requiredFields {
		if input.Get(field) == "" {
			return nil, fmt.Errorf("%s is required", field)
		}
	}

	form := url.Values{}
	form.Set("grant_type", grantType)
	form.Set("client_id", s.config.ElvantoClientID)
	form.Set("client_secret", s.config.ElvantoClientSecret)
	if grantType == "authorization_code" {
		form.Set("code", input.Get("code"))
		form.Set("redirect_uri", input.Get("redirect_uri"))
	} else {
		form.Set("refresh_token", input.Get("refresh_token"))
	}
	return form, nil
}

func (s *Server) cacheTokenResponse(ctx context.Context, token elvanto.TokenResponse, fallbackRefreshToken string) (vault.Entry, error) {
	accessToken := httpx.StringClaim(token, "access_token")
	person, err := s.elvanto.FetchCurrentUser(ctx, accessToken)
	if err != nil {
		return vault.Entry{}, fmt.Errorf("failed to resolve token subject")
	}

	entry := vault.Entry{
		Sub:          person.ID,
		AccessToken:  accessToken,
		RefreshToken: httpx.FirstNonEmpty(httpx.StringClaim(token, "refresh_token"), fallbackRefreshToken),
		ExpiresAt:    elvanto.ExpiresAt(token),
	}
	if err := s.vault.Set(entry); err != nil {
		return vault.Entry{}, err
	}
	return entry, nil
}

func (s *Server) brokerTokenResponse(token elvanto.TokenResponse, brokerToken, brokerRefreshToken string) elvanto.TokenResponse {
	response := make(elvanto.TokenResponse, len(token))
	for key, value := range token {
		response[key] = value
	}
	response["access_token"] = brokerToken
	response["refresh_token"] = brokerRefreshToken
	response["token_type"] = "Bearer"
	response["expires_in"] = int(s.tokens.AccessTTL().Seconds())
	return response
}
