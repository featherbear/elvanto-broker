# Elvanto Broker

`elvanto-broker` adapts Elvanto OAuth/API access into a local integration layer.

It provides:

- An OIDC facade for applications or identity providers that need standard authorization, token, and userinfo endpoints.
- A token broker and API proxy for Elvanto API requests.

For application integration guidance, see [`INTEGRATION.md`](./INTEGRATION.md).

## Endpoints

- `GET /health`: health check.
- `GET /.well-known/oauth-authorization-server`: OAuth authorization server metadata.
- `GET /.well-known/openid-configuration`: OIDC discovery metadata.
- `GET /oidc/auth`: starts Elvanto OAuth authorization.
- `POST /oidc/token`: exchanges Elvanto authorization codes or broker refresh tokens.
- `GET /oidc/userinfo`: returns OIDC-style userinfo from Elvanto.
- `POST /token/exchange`: exchanges a trusted IdP access token for a broker access token.
- `GET|POST /token/issue`: internal token issue endpoint on `TOKEN_ISSUER_LISTEN_ADDRESS` only.
- `/api/*`: Elvanto API proxy using broker tokens, or trusted IdP tokens when explicitly enabled.

## Runtime Config

Core settings:

```text
SERVER_LISTEN_ADDRESS=:8080
ISSUER=http://elvanto-broker:8080

TOKEN_VAULT_DB_PATH=/data/elvanto-broker.db
TOKEN_VAULT_ENCRYPTION_KEY=base64-encoded-32-byte-key

ELVANTO_CLIENT_ID=94483
ELVANTO_CLIENT_SECRET=change-me

BROKER_OIDC_ALLOWED_CLIENTS=elvanto-broker:change-me,another-client:another-secret
BROKER_TOKEN_SIGNING_SECRET=change-me
BROKER_ACCESS_TOKEN_TTL=1h
BROKER_REFRESH_TOKEN_TTL=336h
```

Optional IdP-token validation settings:

```text
IDP_EXPECTED_ISSUER=https://authentik.example.com/application/o/elvanto-broker/
IDP_JWKS_URL=https://authentik.example.com/application/o/elvanto-broker/jwks/
IDP_EXPECTED_AUDIENCE=elvanto-broker
IDP_USER_ID_CLAIM=elvanto_id
ALLOW_IDP_TOKEN_IN_API=false
```

Optional internal token issue settings:

```text
TOKEN_ISSUER_LISTEN_ADDRESS=:8081
ELVANTO_SUB_HEADER=X-Elvanto-Sub
```

Optional CORS restriction:

```text
CORS_ALLOWS_ORIGINS=https://app.example.com,https://*.example.org
```

`BROKER_OIDC_ALLOWED_CLIENTS` is a comma-separated list of `client_id:client_secret` pairs. `/oidc/auth` validates that the broker client ID is allowlisted, and `/oidc/token` validates that client's credentials.

`ELVANTO_CLIENT_ID` and `ELVANTO_CLIENT_SECRET` are the single upstream Elvanto OAuth client used by the broker. Callers do not provide them, and they are not stored in the vault.

## Token Vault

When `/oidc/token` receives a successful Elvanto token response, the broker stores the Elvanto credentials in the token vault and returns broker-issued tokens to the caller.

`TOKEN_VAULT_ENCRYPTION_KEY` is required. It must be a base64-encoded 32-byte key used for AES-256-GCM application-level encryption:

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

The stable subject and expiry timestamp remain plaintext for lookup and operational use.

## Broker Tokens

Broker tokens are JWTs signed with HS256.

Defaults:

- Access token TTL: 1 hour.
- Refresh token TTL: 14 days.
- Access token audience: `access`.
- Refresh token audience: `refresh`.

Set `BROKER_TOKEN_SIGNING_SECRET` in production. If it is unset, the broker generates an in-memory secret on startup, which invalidates broker tokens on restart.

`/oidc/token` issues both broker access and refresh tokens. `/token/exchange` and `/token/issue` issue broker access tokens only.

## IdP Token Validation

IdP token validation is enabled when both of these are set:

```text
IDP_EXPECTED_ISSUER=...
IDP_JWKS_URL=...
```

The broker validates:

- JWT signature using RS256 public keys from `IDP_JWKS_URL`.
- `iss` equals `IDP_EXPECTED_ISSUER`.
- `aud` contains `IDP_EXPECTED_AUDIENCE`, when configured.
- `exp` is in the future.
- `nbf` is not in the future, when present.
- `IDP_USER_ID_CLAIM` exists and maps to a cached Elvanto person ID.

Set `IDP_EXPECTED_AUDIENCE` in production to prevent tokens issued for another app from being replayed at the broker.

## API Proxy

Requests to `/api/*` are forwarded to Elvanto's API. The broker verifies the caller's token, retrieves and refreshes the stored Elvanto token when needed, and forwards the request to Elvanto.

Example:

```sh
curl http://localhost:8080/api/people/currentUser.json \
  -H "Authorization: Bearer BROKER_TOKEN"
```

By default, `/api/*` only accepts broker tokens. To also accept trusted IdP tokens directly, set:

```text
ALLOW_IDP_TOKEN_IN_API=true
```

Prefer `/token/exchange` unless there is a specific reason for the proxy to accept IdP tokens directly.

## Backend Token Issue

`/token/issue` is disabled unless `TOKEN_ISSUER_LISTEN_ADDRESS` is set. When enabled, it runs on a separate internal HTTP server and is not registered on the public `SERVER_LISTEN_ADDRESS` listener.

It is intended for trusted internal services only and does not emit CORS headers.

Example:

```sh
curl http://elvanto-broker:8081/token/issue \
  -H "X-Elvanto-Sub: ELVANTO_PERSON_ID"
```

For local host testing, temporarily publish or port-forward `TOKEN_ISSUER_LISTEN_ADDRESS`; do not expose it publicly.

## Scopes

Supported Elvanto scopes are:

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
