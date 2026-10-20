# Token trust for stateless-auth and msal-exchange

This change completes the follow-up to #173 / PR #182 for the two remaining
cookie-authentication modules. It is stacked on the CSRF changes in PR #183.
Existing installations must configure the policies below before enabling these
handlers. No Portal client, Rust service, or deployed configuration is changed
by this Java PR.

## Signing boundaries

Each enabled policy owns its application validator. Identical administrator-selected
JWKS URLs and CA settings share one source/cache within a configuration snapshot;
ID and API claim policies remain independent. Different endpoints, CA settings or
configuration snapshots never share signing state.
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

HTTPS uses JVM default trust anchors and normal hostname verification. For a
private-CA OAuth endpoint, add public PEM CA certificate paths to that policy:

```yaml
statelessAuth.tokenTrust:
  jwksUri: https://oauth.internal.example/keys
  issuer: urn:com:networknt:oauth2:v1
  audience: urn:com.networknt
  additionalCaFiles: [/etc/gateway/certs/portal-ca.pem]
```

additionalCaFiles extends default roots for that endpoint only. Microsoft's public
roots and the JVM's global SSL settings remain intact. Files may contain PEM
certificate chains and must be readable by the gateway. Do not replace the whole
JVM trust store with a private-only store: that would remove public roots used by
Microsoft and other HTTPS clients. client.yml's private truststore is not inherited;
configure the CA on internalTokenTrust/tokenTrust explicitly. The former OAuth-client
TLS switches do not disable certificate or hostname verification here.

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
  audience: YOUR-GATEWAY-API-CLIENT-UUID
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
not Microsoft Graph's audience. Entra **v2 access tokens use the API application
(client) UUID** in aud. An api:// application-ID URI may be an audience for v1
access tokens; configure the matching v1 issuer in that case. v2 API policies reject
non-UUID audiences at load time. light-oauth mode requires only internal and ID
policies; azure-msal mode requires all three. An explicitly provided API policy is
validated eagerly even in light-oauth mode; there is no request-time policy parsing. Existing cookie/header placement
and opaque CSRF handling are unchanged.

## Expiry, responses and key rotation

All tokens must have exp; nbf is checked when present. clockSkewSeconds is bounded
from 0 to 300. Microsoft tokens cannot bypass lifetime checks via ignoreJwtExpiry.
Internal expiry relaxation is used only to validate an old session for renewal
or logout: an expired access token is never forwarded. Tokens returned by callback,
exchange, refresh and recovery must pass the internal policy and contain the
requested CSRF claim before any session cookie is set. A rejected issuance response
cannot become a success response or execute the original API request.

Invalid signature/policy/lifetime returns an authentication 401. Duplicate eligible
signing keys under one kid are definitive invalid-key errors, not an outage cooldown.
Transport or malformed-JWKS uncertainty returns 503. Existing access/CSRF cookies
are preserved. If OAuth has already issued/rotated a refresh credential but the
returned JWT's key verification is unavailable or pending publication, retain
**only the opaque HttpOnly refresh credential** and return 503
SESSION_VERIFICATION_PENDING. Do not install the unverified JWT or a new CSRF value,
and do not execute the original request. Retrying uses the retained credential,
including after the provider's old-token grace expires. A confirmed signature,
issuer, audience or other application-policy failure never installs new credentials. Logout uses the
same internal authority and policy. An independently invalid or confirmed
unresolvable session can be cleared with trusted browser provenance; a valid
session still needs its request-bound CSRF, and lookup uncertainty cannot clear it.
The CSRF migration's recovery, 409 explicit retry, renewal fallback, and logout
counters remain in effect.

Key lookups share a per-endpoint, per-configuration single-flight future with a
five-second waiter deadline. Known cached keys bypass other kids' in-flight work
and failure cooldowns. Cached keys remain usable during outages for **one hour
past their freshness deadline**, with JWT lifetime/application checks still enforced.
This is an explicit availability/revocation tradeoff: retained keys are discarded
as soon as a successful refresh replaces the set, and retention never extends with
repeated errors. A configuration replacement clears retained state immediately;
reload with a fresh source to fail closed during emergency key revocation.

Freshness uses the smaller of HTTP max-age and 300 seconds (300-second fallback).
Unknown-kid refreshes on a fresh set have a 30-second reprieve; absence during that
reprieve is **uncertain (503)**, not an invalid-token decision. Only a newer successful
HTTP response can establish missing-key evidence. A single bounded, five-second
negative entry records the specifically confirmed missing kid; different random
kids cannot create an unbounded negative cache. Expired key sets can be refreshed
without the fresh-set reprieve. Failed fetches have a five-second cooldown, without
blocking cached known keys. Owner HTTP connect/read timeouts are five seconds,
with no retries; a timed-out waiter never cancels it.

Publish new keys before issuing their tokens, retain old keys for token/cache overlap,
and allow the fresh-set reprieve during rotation. Pending refresh verification retains
the rotated opaque credential so this delay cannot strand the browser on an obsolete
refresh token. New configuration snapshots install fresh source/cache state.

## Validation boundary

Tests exercise generated RSA tokens with colliding key IDs across independent
providers, exact claims on repeated requests, ID/API purpose separation, actual
local HTTPS OAuth/JWKS responses, returned-token rejection, expiry/recovery,
failed configuration snapshots, source replacement, bounded key-lookup waiters
and retry cooldown. These are local component checks; deployed Entra/Portal,
proxy and private-CA configuration still require rollout qualification.
