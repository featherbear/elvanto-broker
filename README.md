# Elvanto Broker

`elvanto-broker` adapts Elvanto OAuth/API access into a local integration layer.

It has two jobs:

- Provide an OIDC facade for apps or IdPs that need standard authorization, token, and userinfo endpoints.
- Function as a token broker for Elvanto API requests

## Endpoints

- `GET /health`: health check
- `GET /oidc/.well-known/oauth-authorization-server`: broker OAuth metadata
- `GET /oidc/auth`: redirects users to Elvanto OAuth
- `POST /oidc/token`: exchanges Elvanto authorization codes or broker refresh tokens
- `GET /oidc/userinfo`: returns OIDC-style userinfo from Elvanto
- `POST /token/exchange`: exchanges a trusted IdP token for a broker token
- `GET|POST /token/issue`: backend-only broker token issue endpoint using a trusted subject header
- `/api/*`: Elvanto API proxy using broker tokens

## Runtime Config

Core settings:

```text
ADDR=:8080
ISSUER=http://elvanto-broker:8080
TOKEN_VAULT_DB_PATH=/data/elvanto-broker.db
BROKER_TOKEN_SIGNING_SECRET=change-me
BROKER_ACCESS_TOKEN_TTL=1h
BROKER_REFRESH_TOKEN_TTL=336h

IDP_ISSUER=http://authentik-server:9000/application/o/authentik-sample-app/
IDP_JWKS_URL=http://authentik-server:9000/application/o/authentik-sample-app/jwks/
AUDIENCE=authentik-sample-app
IDP_USER_ID_CLAIM=elvanto_id
ALLOW_IDP_TOKEN_IN_API=false
```

`AUDIENCE` is the expected JWT `aud` claim. It identifies who the IdP token was issued for. In this local stack, Authentik issues tokens for the `authentik-sample-app` OAuth client, so the broker requires `AUDIENCE=authentik-sample-app`. This prevents a valid token minted for another app from being exchanged at the broker.

## Token Vault

When `/oidc/token` receives a successful Elvanto token response, the broker stores the credentials in the token vault and instead returns a broker token

Broker token defaults:

- Access token TTL: 1 hour
- Refresh token TTL: 14 days
- Signing algorithm: HS256, using `BROKER_TOKEN_SIGNING_SECRET` if set
- Access token audience: `access`
- Refresh token audience: `refresh`

If `BROKER_TOKEN_SIGNING_SECRET` is not set, the broker generates an in-memory secret on startup. That is fine for local testing but invalidates broker tokens on restart.

## IdP Token Exchange

`POST /token/exchange` accepts a trusted IdP access token and returns a short-lived broker access token.

Request:

```sh
curl -X POST http://localhost:8080/token/exchange \
  -H "Authorization: Bearer IDP_ACCESS_TOKEN"
```

Response:

```json
{
  "access_token": "BROKER_JWT",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Verification checks:

- JWT signature via the RS256 public keys from `IDP_JWKS_URL`
- `iss` equals `IDP_ISSUER`
- `aud` contains `AUDIENCE`, when configured
- `exp` is in the future
- `nbf` is not in the future, when present
- `IDP_USER_ID_CLAIM` exists and maps to a cached Elvanto person ID

## API Proxy

Requests to `/api/*` are forwarded to Elvanto's API. The broker verifies the broker token, retrieves (and refreshes) the Elvanto token, and forwards the request to Elvanto.

Example:

```sh
curl http://localhost:8080/api/people/currentUser.json \
  -H "Authorization: Bearer BROKER_TOKEN"
```

By default, `/api/*` only accepts broker tokens. To also accept trusted IdP tokens directly, set:

```text
ALLOW_IDP_TOKEN_IN_API=true
```

## Backend Token Issue

`/token/issue` is intended for backend/proxy use only. It does not emit CORS headers.

Configure the trusted subject header explicitly:

```text
ELVANTO_SUB_HEADER=X-Elvanto-Sub
```

Example:

```sh
curl http://localhost:8080/token/issue \
  -H "X-Elvanto-Sub: ELVANTO_PERSON_ID"
```

Do not expose `/token/issue` publicly unless it is protected by trusted infrastructure

## CORS

`/token/exchange` and `/api/*` support CORS. By default, all origins are allowed.

Restrict browser origins with:

```text
CORS_ALLOWS_ORIGINS=https://app.example.com,https://*.example.org
```

## Scopes

Supported scopes are:

- `openid`
- `profile`
- `email`
- `ManagePeople`
- `ManageGroups`
- `ManageServices`
- `ManageSongs`
- `ManageCalendar`
- `ManageFinancials`
- `AdministerAccount`

## Local Run

```sh
go run ./cmd/elvanto-broker
```
