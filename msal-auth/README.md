# Direct MSAL browser sessions

`MsalAuthHandler` accepts **delegated Entra access tokens for your API** at
`POST /auth/ms/login`. It verifies the signature and application trust policy
before creating session cookies, and repeats those checks before forwarding
cookie tokens as bearer tokens. It does not accept Microsoft Graph access
tokens, ID tokens, or app-only credentials as browser sessions.

## Migration for issue #173

Enabled deployments must now configure a complete trust policy. Missing or
invalid policy values fail configuration loading rather than silently accepting
any Microsoft-signed token. Disabled handlers do not require a policy.

1. In Entra, expose a delegated scope on the API app registration, for example
   `access_as_user`. Grant the SPA client the appropriate delegated permission.
2. Have MSAL request that API scope (for example
   `api://<api-application-id>/access_as_user`) and send the resulting
   **access token** to the login endpoint. Do not send `idToken`.
3. Set the policy below using your tenant, API, and authorized SPA client IDs.
   Obtain the exact issuer from the tenant-specific OpenID metadata document.
   Set `jwksUri` to the trusted metadata document's `jwks_uri` (an HTTPS URL).
   The instance-owned MSAL resolver fetches only this endpoint; it never consults
   shared `JwtVerifier` certificates, JWK/token caches, or `client.yml` provider
   routing. Never derive a key URL from token claims.
4. Set `security-msal.enableJwtCache: false` and restart the gateway. Existing
   cookies must satisfy the new policy on their next request; users with
   incompatible tokens must sign in again. Rejected cookie authentication clears
   both cookies; CSRF failures, signing-key lookup failures (unknown `kid` or an
   unreachable JWKS endpoint) and server-side verifier failures keep them.

Example `msal-auth.yml` for v2 access tokens (replace all example UUIDs):

```yaml
enabled: true
tenantId: "11111111-1111-1111-1111-111111111111"
issuer: "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
audience: "22222222-2222-2222-2222-222222222222" # API application ID
jwksUri: "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/discovery/v2.0/keys"
requiredScopes:
  - access_as_user
allowedClientIds:
  - "33333333-3333-3333-3333-333333333333" # SPA application ID
loginPath: /auth/ms/login
logoutPath: /auth/ms/logout
logoutCsrfEnforced: true
cookieDomain: app.example.com
cookiePath: /
cookieSecure: true
cookieSameSite: Lax
sessionTimeout: 3600
```

In `security-msal.yml`, keep the desired clock skew and set:

```yaml
enableJwtCache: false
```

The effective cache setting must be false. An omitted setting also passes when
the shared configuration default is false; setting it explicitly is recommended.
`requiredScopes` and `allowedClientIds` accept native arrays, JSON-array strings
and comma-separated strings through `values.yml` or environment substitution.
The shipped `.yml` includes all required placeholders; the `.yaml` template and
JSON schema include the same policy fields. Empty defaults fail enabled-policy
validation and are permitted when the handler is disabled.

MSAL uses an instance-owned jose4j verifier and JWKS cache. It does not construct
or consult the shared `JwtVerifier`, so another provider cannot replace its
configuration/certificates or satisfy resolution through a colliding cached `kid`.
There is no JWT claims cache; `enableJwtCache: true` remains unsupported. The
private JWKS cache honors endpoint caching and allows key rotation. Unknown-kid
refreshes are rate limited for 30 seconds. A changed MSAL policy or
`security-msal` map snapshot creates a fresh verifier and key cache.

Signatures must use RS256. HTTPS uses the JVM trust store and hostname verification,
with five-second connect/read timeouts and no transport retries. Deployments using
private certificate authorities must configure their JVM trust store. Shared
client registry/proxy/TLS configuration and `security-msal.jwt.certificate` are not
used by this isolated signing path. `security-msal` still supplies clock skew and
the unsupported JWT-cache guard; `ignoreJwtExpiry` cannot disable expiry checks.

## Policy semantics

- One explicit tenant and issuer are supported per handler configuration.
  `common`, `organizations`, wildcard issuers, and cross-tenant policies are
  not supported.
- `tenantId` and client IDs are canonical lowercase UUIDs. The issuer is an
  exact HTTPS URI whose tenant path matches `tenantId`. Configure only trusted
  metadata issuers, including the appropriate host for sovereign clouds.
- For v2, use the issuer ending in `/<tenantId>/v2.0`, `ver: "2.0"` and the
  API's application-ID audience. The requesting client is checked using `azp`.
- For v1, use the exact metadata issuer ending in `/<tenantId>/` (normally
  `https://sts.windows.net/<tenantId>/`), `ver: "1.0"` and the API's expected
  audience, which may be an application ID URI. The client is checked using
  `appid`. A deployment accepts the configured version only.
- The audience must identify exactly the configured API. All configured scopes
  must occur as complete, case-sensitive entries in the space-delimited `scp`
  claim. `roles` cannot substitute for delegated scopes.
- A nonempty subject is required. Tokens declaring `idtyp: app` are rejected.
  The `typ: JWT` header does not distinguish ID tokens from access tokens;
  the audience and delegated scope policy establish the token's purpose.
- The isolated verifier enforces expiration with the configured
  `security-msal.jwt.clockSkewInSeconds` allowance. The application policy
  applies that same allowance to not-before; it does not duplicate expiry checking.
- Invalid tokens return `401 / ERR10000 / INVALID_AUTH_TOKEN`; expired tokens
  return `401 / ERR10001 / AUTH_TOKEN_EXPIRED` so the SPA can reacquire a token.
  Responses never include token details. Logs use bounded policy-failure categories.
  Unexpected resolver/programming failures retain server-error behavior instead of
  becoming 401 responses. Rejected cookie sessions are cleared, while invalid
  login tokens do not create cookies or reach downstream handlers.
- A failed configuration snapshot remains fail-closed and its failure is cached,
  avoiding repeated parsing and locking on every request. Installing a corrected
  configuration-cache snapshot allows recovery. Downstream APIs remain responsible
  for operation-specific authorization.

## Local validation

```sh
mvn -pl msal-auth -am test
mvn test
```

Regression tests sign local RSA tokens and exercise HTTP login and cookie requests.
Signing-isolation tests serve HTTPS JWKS endpoints with colliding key IDs, run the
production factory in a fresh JVM with no injected verifier, and initialize a
legacy verifier in both orders. They also test endpoint-owned caches and key
rotation. The committed certificate/private key are synthetic test fixtures only. They require
no Entra credentials or network calls to Microsoft. Local tests do not establish
deployment-specific Entra integration.

References: [Microsoft access-token validation](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
and [claims-based authorization](https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation).
