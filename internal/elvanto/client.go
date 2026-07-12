package elvanto

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"elvanto-broker/internal/httpx"
)

// Config contains Elvanto endpoint URLs used by the API/OAuth client.
type Config struct {
	// AuthURL is the Elvanto OAuth authorization endpoint.
	AuthURL string

	// TokenURL is the Elvanto OAuth token endpoint.
	TokenURL string

	// APIURL is the base URL for Elvanto API requests.
	APIURL string

	// UserinfoURL resolves the current Elvanto user for a bearer token.
	UserinfoURL string
}

type Client struct {
	authURL     string
	tokenURL    string
	apiURL      string
	userinfoURL string
	http        *http.Client
}

type TokenResponse map[string]any

type CurrentUserResponse struct {
	Status string   `json:"status"`
	Person []Person `json:"person"`
}

type Person struct {
	ID            string `json:"id"`
	FirstName     string `json:"firstname"`
	PreferredName string `json:"preferred_name"`
	LastName      string `json:"lastname"`
	Email         string `json:"email"`
	Phone         string `json:"phone"`
	Mobile        string `json:"mobile"`
	Username      string `json:"username"`
	Country       string `json:"country"`
	Timezone      string `json:"timezone"`
	Picture       string `json:"picture"`
}

func New(config Config) *Client {
	return &Client{
		authURL:     config.AuthURL,
		tokenURL:    config.TokenURL,
		apiURL:      config.APIURL,
		userinfoURL: config.UserinfoURL,
		http:        &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) AuthURL() string {
	return c.authURL
}

func (c *Client) APIURL() string {
	return c.apiURL
}

func (c *Client) HTTP() *http.Client {
	return c.http
}

func (c *Client) ExchangeToken(ctx context.Context, form url.Values) (TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create Elvanto token request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Elvanto token request failed")
	}
	defer resp.Body.Close()

	var token TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("invalid Elvanto token response")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Elvanto token request failed")
	}
	if httpx.StringClaim(token, "access_token") == "" {
		return nil, fmt.Errorf("Elvanto token response did not include access_token")
	}

	return token, nil
}

func (c *Client) FetchCurrentUser(ctx context.Context, bearer string) (Person, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.userinfoURL, bytes.NewReader(nil))
	if err != nil {
		return Person{}, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return Person{}, fmt.Errorf("failed to fetch Elvanto current user")
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Person{}, fmt.Errorf("Elvanto current user request failed")
	}

	var payload CurrentUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return Person{}, fmt.Errorf("invalid Elvanto current user response")
	}
	if payload.Status != "ok" || len(payload.Person) == 0 {
		return Person{}, fmt.Errorf("Elvanto current user response did not contain a user")
	}

	return payload.Person[0], nil
}

func (p Person) UserinfoClaims() map[string]any {
	claims := map[string]any{
		"sub": p.ID,
	}
	setClaim(claims, "given_name", p.FirstName)
	setClaim(claims, "family_name", p.LastName)
	setClaim(claims, "preferred_username", p.Username)
	setClaim(claims, "email", p.Email)
	setClaim(claims, "phone_number", httpx.FirstNonEmpty(p.Mobile, p.Phone))
	setClaim(claims, "picture", p.Picture)
	setClaim(claims, "zoneinfo", p.Timezone)
	setClaim(claims, "locale", p.Country)
	setClaim(claims, "name", displayName(p))
	return claims
}

func ExpiresAt(token TokenResponse) time.Time {
	expiresIn := httpx.IntClaim(token, "expires_in")
	if expiresIn <= 0 {
		return time.Time{}
	}
	return time.Now().Add(time.Duration(expiresIn) * time.Second)
}

func setClaim(claims map[string]any, key, value string) {
	if value != "" {
		claims[key] = value
	}
}

func displayName(p Person) string {
	if p.PreferredName != "" && p.LastName != "" {
		return p.PreferredName + " " + p.LastName
	}
	if p.PreferredName != "" {
		return p.PreferredName
	}
	if p.FirstName != "" && p.LastName != "" {
		return p.FirstName + " " + p.LastName
	}
	return httpx.FirstNonEmpty(p.FirstName, p.LastName, p.Username, p.Email)
}
