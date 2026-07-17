package app

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"elvanto-broker/internal/elvanto"
	"elvanto-broker/internal/httpx"
	"elvanto-broker/internal/vault"
)

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	if !s.cors.WriteHeaders(w, r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	entry, ok := s.vaultEntryForAPIToken(w, r)
	if !ok {
		return
	}

	target, err := s.apiTargetURL(r.URL)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "invalid Elvanto API URL")
		return
	}
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to create Elvanto API request")
		return
	}
	httpx.CopyHeaders(proxyReq.Header, r.Header)
	httpx.RemoveHopHeaders(proxyReq.Header)
	proxyReq.Header.Set("Authorization", "Bearer "+entry.AccessToken)

	resp, err := s.elvanto.HTTP().Do(proxyReq)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusBadGateway, "server_error", "Elvanto API request failed")
		return
	}
	defer resp.Body.Close()

	httpx.CopyHeaders(w.Header(), resp.Header)
	httpx.RemoveHopHeaders(w.Header())
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("write Elvanto API response: %v", err)
	}
}

func (s *Server) exchangeToken(w http.ResponseWriter, r *http.Request) {
	if !s.cors.WriteHeaders(w, r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !s.idp.Configured() {
		httpx.WriteOAuthError(w, http.StatusServiceUnavailable, "server_error", "IdP token validation is not configured")
		return
	}

	idpToken := httpx.BearerToken(r.Header.Get("Authorization"))
	if idpToken == "" {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", "missing IdP bearer token")
		return
	}
	identity, err := s.idp.Subject(r.Context(), idpToken)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}
	entry, ok := s.vaultEntryForSubject(w, r, identity, "no cached Elvanto token for caller")
	if !ok {
		return
	}
	brokerToken, err := s.tokens.IssueAccess(entry.Sub)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue broker token")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token": brokerToken,
		"token_type":   "Bearer",
		"expires_in":   int(s.tokens.AccessTTL().Seconds()),
	})
}

func (s *Server) issueToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		httpx.WriteOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}

	sub, err := s.elvantoSub(r)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_request", err.Error())
		return
	}
	if sub == "" {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_request", "missing Elvanto subject header")
		return
	}

	entry, ok, err := s.vault.Get(sub)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to read token vault")
		return
	}
	if !ok {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", "no cached token for caller")
		return
	}
	if entry.Expired() {
		refreshed, err := s.refreshVaultEntry(r.Context(), entry)
		if err != nil {
			httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", err.Error())
			return
		}
		entry = refreshed
	}

	brokerToken, err := s.tokens.IssueAccess(entry.Sub)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue broker token")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token": brokerToken,
		"token_type":   "Bearer",
		"expires_in":   int(s.tokens.AccessTTL().Seconds()),
	})
}

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.vaultEntryForBrokerToken(w, r)
	if !ok {
		return
	}

	person, err := s.elvanto.FetchCurrentUser(r.Context(), entry.AccessToken)
	if err != nil {
		refreshed, refreshErr := s.refreshVaultEntry(r.Context(), entry)
		if refreshErr == nil {
			person, err = s.elvanto.FetchCurrentUser(r.Context(), refreshed.AccessToken)
		}
	}
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}

	httpx.WriteJSON(w, http.StatusOK, person.UserinfoClaims())
}

func (s *Server) vaultEntryForBrokerToken(w http.ResponseWriter, r *http.Request) (vault.Entry, bool) {
	brokerToken := httpx.BearerToken(r.Header.Get("Authorization"))
	if brokerToken == "" {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", "missing broker bearer token")
		return vault.Entry{}, false
	}

	sub, err := s.tokens.AccessSubject(brokerToken)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return vault.Entry{}, false
	}

	entry, ok, err := s.vault.Get(sub)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to read token vault")
		return vault.Entry{}, false
	}
	if !ok {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", "invalid broker token")
		return vault.Entry{}, false
	}
	if !entry.Expired() {
		return entry, true
	}

	refreshed, err := s.refreshVaultEntry(r.Context(), entry)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return vault.Entry{}, false
	}
	return refreshed, true
}

func (s *Server) vaultEntryForAPIToken(w http.ResponseWriter, r *http.Request) (vault.Entry, bool) {
	token := httpx.BearerToken(r.Header.Get("Authorization"))
	if token == "" {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", "missing bearer token")
		return vault.Entry{}, false
	}

	if sub, err := s.tokens.AccessSubject(token); err == nil {
		return s.vaultEntryForSubject(w, r, sub, "invalid broker token")
	}
	if !s.idp.AllowTokenInAPI() {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", "invalid broker token")
		return vault.Entry{}, false
	}
	identity, err := s.idp.Subject(r.Context(), token)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return vault.Entry{}, false
	}
	return s.vaultEntryForSubject(w, r, identity, "no cached Elvanto token for caller")
}

func (s *Server) vaultEntryForSubject(w http.ResponseWriter, r *http.Request, sub, missingMessage string) (vault.Entry, bool) {
	entry, ok, err := s.vault.Get(sub)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "server_error", "failed to read token vault")
		return vault.Entry{}, false
	}
	if !ok {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", missingMessage)
		return vault.Entry{}, false
	}
	return s.refreshEntryIfNeeded(w, r, entry)
}

func (s *Server) refreshEntryIfNeeded(w http.ResponseWriter, r *http.Request, entry vault.Entry) (vault.Entry, bool) {
	if !entry.Expired() {
		return entry, true
	}
	refreshed, err := s.refreshVaultEntry(r.Context(), entry)
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return vault.Entry{}, false
	}
	return refreshed, true
}

func (s *Server) refreshVaultEntry(ctx context.Context, entry vault.Entry) (vault.Entry, error) {
	_, refreshed, err := s.refreshVaultEntryToken(ctx, entry)
	return refreshed, err
}

func (s *Server) refreshVaultEntryToken(ctx context.Context, entry vault.Entry) (elvanto.TokenResponse, vault.Entry, error) {
	if entry.RefreshToken == "" {
		return nil, vault.Entry{}, fmt.Errorf("cached token has no refresh_token")
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", s.config.ElvantoClientID)
	form.Set("client_secret", s.config.ElvantoClientSecret)
	form.Set("refresh_token", entry.RefreshToken)

	token, err := s.elvanto.ExchangeToken(ctx, form)
	if err != nil {
		return nil, vault.Entry{}, err
	}
	refreshed, err := s.cacheTokenResponse(ctx, token, entry.RefreshToken)
	return token, refreshed, err
}

func (s *Server) elvantoSub(r *http.Request) (string, error) {
	if strings.TrimSpace(s.elvantoSubHeader) == "" {
		return "", fmt.Errorf("ELVANTO_SUB_HEADER is not configured")
	}
	return strings.TrimSpace(r.Header.Get(s.elvantoSubHeader)), nil
}
