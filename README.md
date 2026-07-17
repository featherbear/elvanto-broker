# Elvanto Broker

`elvanto-broker` adapts Elvanto OAuth/API access into a local integration layer.

It has two jobs:

- Provide an OIDC facade for apps or IdPs that need standard authorization, token, and userinfo endpoints.
- Function as a token broker for Elvanto API requests

## Endpoints

- `GET /health`: health check
- `GET /.well-known/oauth-authorization-server`: OAuth authorization server metadata
- `GET /.well-known/openid-configuration`: OIDC discovery metadata
- `GET /oidc/auth`: redirects users to Elvanto OAuth
- `POST /oidc/token`: exchanges Elvanto authorization codes or broker refresh tokens
- `GET /oidc/userinfo`: returns OIDC-style userinfo from Elvanto
- `POST /token/exchange`: exchanges a trusted IdP token for a broker token
- `GET|POST /token/issue`: internal token issue endpoint on `TOKEN_ISSUER_LISTEN_ADDRESS` only
- `/api/*`: Elvanto API proxy using broker tokens

## Runtime Config

Core settings:

```text
SERVER_LISTEN_ADDRESS=:8080
# Optional. If unset, /token/issue is disabled.
TOKEN_ISSUER_LISTEN_ADDRESS=:8081
ISSUER=http://elvanto-broker:8080
TOKEN_VAULT_DB_PATH=/data/elvanto-broker.db
TOKEN_VAULT_ENCRYPTION_KEY=base64-encoded-32-byte-key
ELVANTO_CLIENT_ID=94483
ELVANTO_CLIENT_SECRET=change-me
BROKER_OIDC_ALLOWED_CLIENTS=elvanto-broker:change-me,another-client:another-secret
BROKER_TOKEN_SIGNING_SECRET=change-me
BROKER_ACCESS_TOKEN_TTL=1h
BROKER_REFRESH_TOKEN_TTL=336h

IDP_EXPECTED_ISSUER=http://authentik-server:9000/application/o/authentik-sample-app/
IDP_JWKS_URL=http://authentik-server:9000/application/o/authentik-sample-app/jwks/
IDP_EXPECTED_AUDIENCE=authentik-sample-app
IDP_USER_ID_CLAIM=elvanto_id
ALLOW_IDP_TOKEN_IN_API=false
```

`IDP_EXPECTED_AUDIENCE` is the expected JWT `aud` claim. It identifies who the IdP token was issued for. In this local stack, Authentik issues tokens for the `authentik-sample-app` OAuth client, so the broker requires `IDP_EXPECTED_AUDIENCE=authentik-sample-app`. This prevents a valid token minted for another app from being exchanged at the broker.

`BROKER_OIDC_ALLOWED_CLIENTS` identifies clients calling the broker OIDC facade as comma-separated `client_id:client_secret` pairs. `/oidc/auth` validates that the provided broker client ID is allowlisted, and `/oidc/token` validates that client's broker credentials.

`ELVANTO_CLIENT_ID` and `ELVANTO_CLIENT_SECRET` are the single global Elvanto OAuth client used upstream by the broker. They are not accepted from callers and are not stored in the vault.

## Token Vault

When `/oidc/token` receives a successful Elvanto token response, the broker stores the credentials in the token vault and instead returns a broker token.

`TOKEN_VAULT_ENCRYPTION_KEY` is required. It must be a base64-encoded 32-byte key used for AES-256-GCM application-level encryption. Generate one with:

```sh
openssl rand -base64 32
```

Keep this key stable and secret. Losing it makes encrypted vault entries unreadable. Rotating it requires a migration that decrypts with the old key and rewrites with the new key.

`TOKEN_VAULT_DB_PATH` selects the vault backend:

- File path, for example `/data/elvanto-broker.db`: local bbolt vault.
- SQL URL, for example `sql://username:password@host:5432/database`: PostgreSQL vault.

The `sql://` format is converted internally to a PostgreSQL connection URL. `postgres://` and `postgresql://` URLs are also accepted.

The PostgreSQL backend creates this table automatically if it does not exist:

```sql
CREATE TABLE IF NOT EXISTS token_vault_entries (
    sub text PRIMARY KEY,
    access_token text NOT NULL,
    refresh_token text NOT NULL DEFAULT '',
    expires_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);
```

The vault encrypts these fields before writing to either backend:

- `access_token`
- `refresh_token`

The stable subject and expiry timestamp remain plaintext for lookup and operational use. Existing plaintext vault entries from earlier local runs are still readable and will be rewritten encrypted the next time they are refreshed or updated.

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
- `iss` equals `IDP_EXPECTED_ISSUER`
- `aud` contains `IDP_EXPECTED_AUDIENCE`, when configured
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

`/token/issue` is disabled unless `TOKEN_ISSUER_LISTEN_ADDRESS` is set. When enabled, it runs on a separate internal HTTP server bound to `TOKEN_ISSUER_LISTEN_ADDRESS`. It is not registered on the public `SERVER_LISTEN_ADDRESS` listener and does not emit CORS headers.

In Docker Compose, only `SERVER_LISTEN_ADDRESS` is published to the host. `TOKEN_ISSUER_LISTEN_ADDRESS` is exposed only on the Docker network so other backend services can call it as:

```text
http://elvanto-broker:8081/token/issue
```

Configure the trusted subject header explicitly:

```text
ELVANTO_SUB_HEADER=X-Elvanto-Sub
```

Example:

```sh
curl http://elvanto-broker:8081/token/issue \
  -H "X-Elvanto-Sub: ELVANTO_PERSON_ID"
```

For local host testing, temporarily publish or port-forward `TOKEN_ISSUER_LISTEN_ADDRESS`; do not expose it publicly.

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
