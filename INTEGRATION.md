# Integration Guide

This document is for an AI agent integrating an application with `elvanto-broker`.

Use the broker as the access layer for Elvanto. Once integrated, applications should not call Elvanto API endpoints directly.

## API Proxy

Replace this Elvanto API base URL:

```text
https://elvanto.com/api/v1/*
```

with the broker API proxy:

```text
https://BROKER_HOST/api/*
```

Example:

```text
https://elvanto.com/api/v1/people/currentUser.json
```

becomes:

```text
https://BROKER_HOST/api/people/currentUser.json
```

Preserve the path, HTTP method, query string, and request body. Only replace the base URL.

By default, `/api/*` requires a broker access token:

```http
Authorization: Bearer BROKER_ACCESS_TOKEN
```

The broker validates the caller's token, looks up the associated Elvanto credentials, refreshes them when needed, and forwards the request to Elvanto.

## Authentik Setup

Use these steps when Authentik is the IdP that applications sign into before calling the broker.

## Signing Key

Configure the Authentik OAuth2/OIDC provider with a **Signing Key**.

When a signing key is selected, Authentik signs access tokens with RS256 and publishes the public key through the provider JWKS endpoint. This is required for the broker's IdP verifier, which validates trusted IdP tokens through `IDP_JWKS_URL`.

Do not leave the signing key unset for this use case. Without a signing key, Authentik signs JWTs symmetrically with the provider client secret, producing HS256 tokens that this broker does not validate as IdP tokens.

Configure the broker with the Authentik provider issuer and JWKS URL:

```text
IDP_EXPECTED_ISSUER=https://AUTHENTIK_HOST/application/o/AUTHENTIK_APP_SLUG/
IDP_JWKS_URL=https://AUTHENTIK_HOST/application/o/AUTHENTIK_APP_SLUG/jwks/
IDP_EXPECTED_AUDIENCE=AUTHENTIK_PROVIDER_CLIENT_ID
```

`IDP_EXPECTED_AUDIENCE` is optional in code but should be set in production. In Authentik, the access token audience is commonly the OAuth2 provider client ID.

## Offline Access

Enable the `offline_access` scope mapping in the Authentik OAuth2/OIDC provider if applications need Authentik refresh tokens.

Applications must also request the `offline_access` scope during authorization. Authentik requires both provider support and client request before issuing refresh tokens.

This is separate from broker refresh tokens. Broker refresh tokens are issued by `/oidc/token` when an application authenticates directly to the broker OIDC facade.

## Elvanto ID Claim

The broker needs a stable IdP claim that maps the signed-in Authentik user to an Elvanto person ID already stored in the broker token vault.

Create an Authentik OAuth2 scope mapping that emits an Elvanto ID claim in access tokens. A common claim name is:

```text
elvanto_id
```

Example Authentik scope mapping expression:

```python
return {
    "elvanto_id": request.user.attributes.get("elvanto_id"),
}
```

Add the scope mapping to the Authentik OAuth2/OIDC provider. If the mapping is scope-gated, make sure applications request the corresponding scope.

Configure the broker to read that claim:

```text
IDP_USER_ID_CLAIM=elvanto_id
```

The claim value must match the Elvanto person ID used as the broker vault subject. If the claim is missing or does not match a cached vault entry, `/token/exchange` and direct IdP-token API access will fail.

## Usage Modes

Choose one mode based on who owns authentication and how trusted the caller is.

## Standalone Broker OIDC

Use this mode when the application authenticates directly with `elvanto-broker` as its OIDC provider.

Configure the application with the authorization code grant:

```text
Authorization URL: https://BROKER_HOST/oidc/auth
Token URL:         https://BROKER_HOST/oidc/token
Userinfo URL:      https://BROKER_HOST/oidc/userinfo
```

The client ID and client secret must match an entry in `BROKER_OIDC_ALLOWED_CLIENTS`.

Flow:

1. Redirect the user to `https://BROKER_HOST/oidc/auth`.
2. Receive the authorization-code callback at the application's redirect URI.
3. Exchange the authorization code at `https://BROKER_HOST/oidc/token`.
4. Use the returned broker `access_token` for `/api/*` requests.
5. Use `https://BROKER_HOST/oidc/userinfo` if OIDC-style profile data is required.
6. Otherwise, use `https://BROKER_HOST/api/people/currentUser.json` for Elvanto's current-user API response.

`/oidc/token` can issue broker refresh tokens and accepts `grant_type=refresh_token` to rotate broker tokens.

## IdP Token Exchange

Use this mode when applications authenticate through an external IdP such as Authentik, and the broker should trust that IdP's access tokens.

Setup:

1. Configure `elvanto-broker` as a federated, social-login, or external OIDC source so users can authorize Elvanto access and populate the broker token vault.
2. Configure the broker to trust and verify the IdP access token with `IDP_EXPECTED_ISSUER`, `IDP_JWKS_URL`, `IDP_USER_ID_CLAIM`, and preferably `IDP_EXPECTED_AUDIENCE`.
3. Ensure the IdP access token contains the Elvanto ID claim configured by `IDP_USER_ID_CLAIM`.

Application flow:

1. Sign the user into the application through the IdP.
2. Obtain an IdP access token for the signed-in user.
3. Exchange the IdP access token for a broker access token:

```http
POST https://BROKER_HOST/token/exchange
Authorization: Bearer IDP_ACCESS_TOKEN
```

Successful response:

```json
{
  "access_token": "BROKER_ACCESS_TOKEN",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Use `BROKER_ACCESS_TOKEN` for `/api/*` requests.

## Direct IdP Tokens In The API Proxy

Only use this mode when the broker is explicitly configured to accept IdP tokens directly:

```text
ALLOW_IDP_TOKEN_IN_API=true
```

Then the application may call `/api/*` with:

```http
Authorization: Bearer IDP_ACCESS_TOKEN
```

Prefer `/token/exchange` unless there is a specific operational reason to let the API proxy accept IdP tokens directly.

## Server Impersonation

Use this mode only for trusted internal services that already know the Elvanto subject/person ID for the user they are acting as.

`/token/issue` runs on the broker's internal token issuer listener when `TOKEN_ISSUER_LISTEN_ADDRESS` is configured. It is not intended for browsers or public internet exposure.

The internal service passes the configured subject header and value:

```http
GET http://BROKER_INTERNAL_HOST/token/issue
X-Elvanto-Sub: ELVANTO_PERSON_ID
```

The header name is configured by the broker:

```text
ELVANTO_SUB_HEADER=X-Elvanto-Sub
```

Successful response:

```json
{
  "access_token": "BROKER_ACCESS_TOKEN",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Use the returned broker token for `/api/*` requests.

## Checklist

1. Choose the usage mode: standalone broker OIDC, IdP token exchange, direct IdP-token proxy access, or server impersonation.
2. For Authentik IdP use, configure a signing key so access tokens are RS256 and verifiable through JWKS.
3. For Authentik IdP use, add an Elvanto ID claim scope and set `IDP_USER_ID_CLAIM` to that claim name.
4. Replace every `https://elvanto.com/api/v1/*` API call with `https://BROKER_HOST/api/*`.
5. Send `Authorization: Bearer BROKER_ACCESS_TOKEN` on `/api/*` requests unless direct IdP tokens are explicitly enabled.
6. Preserve existing Elvanto API paths, methods, query parameters, and request bodies.
7. Handle `401` responses by obtaining a fresh token and retrying according to the application's authentication policy.
8. Do not store or expose Elvanto OAuth client secrets in the application; the broker owns the upstream Elvanto OAuth credentials.
