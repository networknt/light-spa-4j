# Token trust for stateless-auth and msal-exchange

This change completes the follow-up to #173 / PR #182 for the two remaining
cookie-authentication modules. It is stacked on the CSRF changes in PR #183.
Existing installations must configure the policies below before enabling these
handlers. No Portal client, Rust service, or deployed configuration is changed
by this Java PR.

## Signing boundaries

Each enabled policy owns an RS256 verifier, HTTPS JWKS source and key cache.
Authentication never reads light-4j JwtVerifier's static certificates, audience
maps or JWT/JWK caches, and never chooses a key server through client.yml routing.
The configured endpoint is the sole authority for that policy. Token jku/x5u
headers do not select the source. client.yml remains responsible for outbound
OAuth token requests; its key-server settings no longer configure these handlers.

The policies check signature, exact issuer and exactly one configured audience
on every use. There is no verified-token cache that can skip these checks. A new
configuration map creates new policy/resolver instances; invalid snapshots remain
failed until a replacement configuration is supplied. Disabled handlers require
no trust policies. Trust maps can be supplied as native YAML objects or JSON
object strings through the production placeholders. Scope/client lists accept
native arrays, JSON-array strings or CSV strings.

HTTPS uses JVM trust anchors and normal hostname verification. For a private CA,
configure the JVM trust store, for example `-Djavax.net.ssl.trustStore=/path/to/ca.jks`
and its password through your normal secret/runtime configuration. The former
OAuth-client TLS switches do not disable validation for this independent source.

## Stateless authorization-code and social-login sessions

Configure a light-oauth access-token policy in values.yml:

```yaml
statelessAuth.tokenTrust:
  jwksUri: https://oauth.example/oauth2/your-host/keys
  issuer: urn:com:networknt:oauth2:v1
  audience: urn:com.networknt
  clockSkewSeconds: 0
```

Use the actual issuer and audience emitted by your own light-oauth deployment;
the URNs above illustrate the existing Java fixture contract, not a universal
Rust/Java issuer setting. The policy also covers Google session issuance and
Google account-link session verification, and Facebook session issuance.

## Microsoft exchange: three distinct roles

The exchange Authorization bearer remains a Microsoft **ID token** for the SPA.
It is sent to the OAuth exchange provider as an ID-token subject; the optional
X-MSAL-Access-Token bearer is a separate delegated **API access token**. An ID
token is never forwarded as an API authorization token.

```yaml
msal-exchange.internalTokenTrust:
  jwksUri: https://oauth.example/oauth2/your-host/keys
  issuer: urn:com:networknt:oauth2:v1
  audience: urn:com.networknt
  clockSkewSeconds: 0

msal-exchange.subjectTokenTrust:
  jwksUri: https://login.microsoftonline.com/YOUR-TENANT-UUID/discovery/v2.0/keys
  tenantId: YOUR-TENANT-UUID
  issuer: https://login.microsoftonline.com/YOUR-TENANT-UUID/v2.0
  audience: YOUR-SPA-CLIENT-UUID
  clockSkewSeconds: 0

# Required only for authorizationToken: azure-msal.
msal-exchange.apiTokenTrust:
  jwksUri: https://login.microsoftonline.com/YOUR-TENANT-UUID/discovery/v2.0/keys
  tenantId: YOUR-TENANT-UUID
  issuer: https://login.microsoftonline.com/YOUR-TENANT-UUID/v2.0
  audience: api://YOUR-GATEWAY-API
  requiredScopes: [gateway.read]
  allowedClientIds: [YOUR-SPA-CLIENT-UUID]
  clockSkewSeconds: 0
```

Replace all placeholders with actual values. Tenant and client IDs must be
canonical UUIDs. Microsoft issuer paths must identify that tenant, with `/v2.0`
or the v1 `/<tenant>/` path; common/organizations authorities are not accepted as
issuers. Configure the exact issuer from the deployment's metadata (including
sovereign clouds where appropriate). The token ver must match the issuer version.
The ID policy requires a user subject, a nonce claim, no delegated scp claim and
no `idtyp: app`. Its audience is the SPA client ID. This is purpose validation,
not a new nonce challenge protocol: the gateway does not assert that the nonce
matches gateway-generated login state. The SPA retains its MSAL login/nonce flow.

The API policy requires a user subject, all configured delegated scp scopes, an
allowed azp (v2) or appid (v1), and no `idtyp: app`. Use the API's actual audience,
not Microsoft Graph's audience. light-oauth mode needs only the internal and ID
policies; azure-msal mode requires all three. Existing cookie/header placement
and opaque CSRF handling are unchanged.

## Expiry, responses and key rotation

All tokens must have exp; nbf is checked when present. clockSkewSeconds is bounded
from 0 to 300. Microsoft tokens cannot bypass lifetime checks via ignoreJwtExpiry.
Internal expiry relaxation is used only to validate an old session for renewal
or logout: an expired access token is never forwarded. Tokens returned by callback,
exchange, refresh and recovery must pass the internal policy and contain the
requested CSRF claim before any session cookie is set. A rejected issuance response
cannot become a success response or execute the original API request.

Invalid signature/policy/lifetime returns an authentication 401. Transport or
malformed-JWKS uncertainty returns 503 and preserves cookies. Logout uses the
same internal authority and policy. An independently invalid or confirmed
unresolvable session can be cleared with trusted browser provenance; a valid
session still needs its request-bound CSRF, and lookup uncertainty cannot clear it.
The CSRF migration's recovery, 409 explicit retry, renewal fallback, and logout
counters remain in effect.

Key lookups share a per-policy single-flight future with a five-second waiter
deadline. Waiter timeouts do not cancel the owner. The owner uses five-second
connect/read timeouts and no HTTP retries. Failed lookups have a five-second
cooldown. jose4j owns the successful JWKS cache (300-second fallback, respecting
provider HTTP cache headers) and a 30-second refresh reprieve for unknown key IDs.
Publish new keys before issuing tokens with them, retain old keys for the token
lifetime and cache overlap, and allow the refresh reprieve during rotation.
A configuration replacement installs a fresh source/cache immediately.

## Validation boundary

Tests exercise generated RSA tokens with colliding key IDs across independent
providers, exact claims on repeated requests, ID/API purpose separation, actual
local HTTPS OAuth/JWKS responses, returned-token rejection, expiry/recovery,
failed configuration snapshots, source replacement, bounded key-lookup waiters
and retry cooldown. These are local component checks; deployed Entra/Portal,
proxy and private-CA configuration still require rollout qualification.
