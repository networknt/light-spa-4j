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
   Keep the signing-key configuration in `security-msal`/`client.yml` pointed
   at the matching trusted Entra authority. Never derive a key URL from token
   claims.
4. Explicitly disable the shared JWT cache and restart the gateway. Existing
   cookies must satisfy the new policy on their next request; users with
   incompatible tokens must sign in again.

Example `msal-auth.yml` for v2 access tokens (replace all example UUIDs):

```yaml
enabled: true
tenantId: "11111111-1111-1111-1111-111111111111"
issuer: "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
audience: "22222222-2222-2222-2222-222222222222" # API application ID
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

In `security-msal.yml`, retain the existing signing-key configuration and set:

```yaml
enableJwtCache: false
```

The verifier's shared cache can return claims verified under another trust
context and skips audience validation on cache hits. This handler rejects
cache-enabled configuration until the shared cache is safe for multiple
verification policies. Repeated requests therefore reverify signatures as well
as claims. `bootstrapFromKeyService` does not replace the application policy.

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
- Expiration and not-before times are enforced with the configured
  `security-msal.jwt.clockSkewInSeconds` allowance.
- Claim failures return a generic 401 and never create session cookies or
  forward the token. Downstream APIs remain responsible for operation-specific
  authorization.

## Local validation

```sh
mvn -pl msal-auth -am test
mvn test
```

Regression tests sign local RSA tokens and execute the real JWT verifier with a
local key resolver, then exercise HTTP login and cookie requests. They require
no Entra credentials or network calls to Microsoft. Local tests do not establish
deployment-specific Entra integration.

References: [Microsoft access-token validation](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
and [claims-based authorization](https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation).
